/*******************************************************************************
* Copyright (c) 2015 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#ifndef _XMON_API_H
#define _XMON_API_H

#include "common_types.h"
#include "mon_callback.h"
#include "mon_api.h"

typedef void *view_handle_t; /* Corresponds to (guest_view_t *) inside xmon_api */
#define VIEW_INVALID_HANDLE ((view_handle_t)NULL)

/* mon_defs.h has #define MON_MAX_GUESTS_SUPPORTED 4 */
#define MAX_GUESTS_SUPPORTED_BY_XMON 4

/* Status of registering MSR */
typedef enum {
	MSR_ID_INVALID = -1,
	MSR_REG_FAIL,
	MSR_REG_OK
} msr_reg_status_t;

/* Inject exception type */
typedef enum {
	EXCEPTION_TYPE_UD = 6,  /* 6 is the #UD vector */
	EXCEPTION_TYPE_GP = 13, /* 13 is the #GP vector */
	EXCEPTION_TYPE_NONE = 256
} exception_type_t;

/* Update type */
typedef enum {
	VIEW_UPDATE_PERMISSIONS_ONLY = 0,
	VIEW_UPDATE_MAPPING,    /* Add, Remap mapping */
	VIEW_REMOVE_MAPPING     /* Remove mapping */
} view_update_type_t;

typedef struct {
	guest_id_t	guest_id;
	uint16_t	padding[3];
	view_handle_t	view;
} view_invalidation_data_t;

/* VMEXIT reason */
typedef struct {
	uint32_t	reason; /* basic reason */
	uint32_t	padding;
	uint64_t	qualification;
	uint64_t	gva; /* GVA valid only in memory events */
} vmexit_reason_t;

/* mon wrapper functions: */

#define XMON_DEADLOOP_LOG(FILE_CODE)  MON_DEADLOOP_LOG(FILE_CODE)
#define XMON_ASSERT_LOG(FILE_CODE, __condition) MON_ASSERT_LOG(FILE_CODE, \
	__condition)


/*-------------------------------------------------------*
*  FUNCTION : xmon_malloc(uint32_t size)
*  PURPOSE  : Allocates contiguous buffer of given size, filled with zeroes
*  ARGUMENTS: IN uint32_t size - size of the buffer in bytes
*  RETURNS  : void*  address of allocted buffer if OK, NULL if failed
*-------------------------------------------------------*/
#define xmon_malloc mon_malloc


/*-------------------------------------------------------*
*  FUNCTION : xmon_mfree()
*  PURPOSE  : Release previously allocated buffer
*  ARGUMENTS: IN void *p_buffer - buffer to be released
*  RETURNS  : void
*-------------------------------------------------------*/
#define xmon_mfree  mon_mfree


/*-------------------------------------------------------*
*  FUNCTION : xmon_page_alloc()
*  PURPOSE  : Allocates contiguous buffer of given size
*  ARGUMENTS: IN HEAP_PAGE_INT number_of_pages - size of the buffer in 4K pages
*  RETURNS  : void*  address of allocted buffer if OK, NULL if failed
*-------------------------------------------------------*/
#define xmon_page_alloc   mon_page_alloc


/*-------------------------------------------------------*
*  FUNCTION : xmon_page_free()
*  PURPOSE  : Release previously allocated buffer
*  ARGUMENTS: IN void *p_buffer - buffer to be released
*  RETURNS  : void
*-------------------------------------------------------*/
#define xmon_page_free  mon_page_free


/*-------------------------------------------------------*
*  FUNCTION : xmon_memory_allocate(uint32_t size)
*  PURPOSE  : Allocates contiguous buffer of given size, filled with zeroes
*  ARGUMENTS: IN uint32_t size - size of the buffer in bytes
*  RETURNS  : void*  address of allocted buffer if OK, NULL if failed
*             returned buffer is always 4K page alinged
*-------------------------------------------------------*/
#define xmon_memory_alloc  mon_memory_alloc


#define xmon_memset mon_memset

#define xmon_memcpy  mon_memcpy

#define xmon_zeromem  mon_zeromem

#define xmon_lock_memcpy mon_lock_memcpy


/*-------------------------------------------------------*
*  FUNCTION : int xmon_vprintf(const char *format, va_list args);
*  PURPOSE  : Allocates contiguous buffer of given size, filled with zeroes
*  ARGUMENTS: format - C string that contains a format string that follows
*  the same specifications as format in printf.
*             args - Depending on the format string, the function may expect
*  a sequence of additional arguments, each containing a value to be used to
*  replace a format specifier in the format string
*  RETURNS  : On success, the total number of characters written is returned.
*             This count does not include the additional null-character
*             automatically appended at the end of the string.
*              On failure, a negative number is returned.
*-------------------------------------------------------*/
#define xmon_vprintf mon_vprintf

/* xmon event handlers */

/*-------------------------------------------------------*
*  PURPOSE  : Plugin initialization
*  ARGUMENTS: num_of_cpus (IN) -- number of CPUs
*             guest_data  (IN) -- Guest Data
*             mem_config  (IN) -- memory configuration
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*initialize_event_handler_t) (uint16_t num_of_cpus,
						 guest_data_t *guest_data,
						 memory_config_t *mem_config);


/*-------------------------------------------------------*
*  PURPOSE  : Plugin initialization after APs launch guest
*  ARGUMENTS: num_of_cpus (IN) -- number of CPUs
*             guest_data  (IN) -- Guest Data
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*initialize_after_aps_started_event_handler_t)(uint16_t
								  num_of_cpus,
								  guest_data_t *
								  guest_data);


/*-------------------------------------------------------*
*  PURPOSE  : Report the EPT Violation Event to Handler
*             and handle the event accordingly
*  ARGUMENTS: vcpu_id                (IN) -- Pointer of
*                                           Guest Virtual
*                                           CPU
*             qualification         (IN) -- IA32_VMX_EXIT_
*                                           QUALIFICATION
*             guest_linear_address  (IN) -- Destination
*                                           GVA
*             guest_physical_address(IN) -- Destination
*                                           GPA
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*ept_violation_event_handler_t)(const guest_vcpu_t *vcpu_id,
						   uint64_t qualification,
						   uint64_t guest_linear_address,
						   uint64_t
						   guest_physical_address);


/*-------------------------------------------------------*
*  PURPOSE  : Report the Write Access to the given MSR to
*             Handler. According to Handler's response,
*             setup dispatchib or allow the access. For
*             MSR EFER and PAT, enable MTF.
*  ARGUMENTS: vcpu_id     (IN) -- Pointer of Guest Virtual
*                                 CPU
*             msr_id      (IN) -- MSR ID
*             mon_handled (IN) -- TRUE: default handled by
*                                 xmon;
*                                 FALSE: not handled by
*                                 xmon
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*msr_write_event_handler_t)(const guest_vcpu_t *vcpu_id,
					       uint32_t msr_id,
					       boolean_t mon_handled);

/*-------------------------------------------------------*
*  PURPOSE  : Report the IO Access to the given port to
*             Handler. According to Handler's response,
*             setup dispatchib, allow, deny the access.For
*             ALLOW access, enable MTF.
*  ARGUMENTS: vcpu_id           (IN) -- Pointer of Guest Virtual CPU
*             port_id           (IN) -- port ID
*             is_read_access    (IN) -- read/write access
*             is_string_intr    (IN) -- INS/OUTS
*             is_rep_prefeix    (IN) -- reps
*             rep_count         (IN) -- if reps, then the rep count?
*             is_owned_by_xmon  (IN) -- 1(owner-xmon); 0(owner- Plugin)
*             value_gva_ptr     (IN) -- pointer to io values
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*io_access_event_handler_t)(const guest_vcpu_t *vcpu_id,
					       uint16_t port_id,
					       uint16_t port_size,
boolean_t is_read_access,
					       boolean_t is_string_intr,
					       boolean_t is_rep_prefix,
uint32_t rep_count,
					       boolean_t io_owned_by_xmon,
					       uint64_t value_gva_ptr);


/*-------------------------------------------------------*
*  PURPOSE  : Set active view to the given view
*  ARGUMENTS: vcpu_id   (IN) -- Pointer of Guest Virtual
*                              CPU
*             handle   (IN) -- View Index
*             update_hw(IN) -- TRUE to set the EPTP in the
*                              VMCS(Hardware) and update
*                              state(Software)
*                              FALSE will only update the
*                              Plugin and xmon state
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*fvs_set_active_view_event_handler_t)(const guest_vcpu_t *
							 vcpu_id,
							 uint64_t handle,
							 boolean_t update_hw);


/*-------------------------------------------------------*
*  PURPOSE  : Report teardown event to Handler
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             nonce   (IN) -- Address of Event specific
*                             data
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*mon_teardown_event_handler_t)(const guest_vcpu_t *vcpu_id,
						  uint64_t nonce);


/*-------------------------------------------------------*
*  PURPOSE  : Report the invalid FVS event to Handler.
*             Handler is expected to return either
*             a) EVENT_RESPONSE_DISPTACHIB: we invoke
*             IB agent;
*             c) EVENT_RESPONSE_EXCEPTION: injects
*             the specified exception to guest.
*             b) If not DISPATCHIB: we inject #UD.
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             reg     (IN) -- Invalid View Index
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*invalid_fvs_event_handler_t)(const guest_vcpu_t *vcpu_id,
						 uint64_t reg);


/*-------------------------------------------------------*
*  PURPOSE  : Report the Preemption timer event to Handler
*             Currently Handler's response is ignored
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*vmx_preemption_timer_event_handler_t)(const guest_vcpu_t *
							  vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : Implementation of VMCALL
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             arg     (IN) -- VMCALL argument, assumed valid
*  RETURNS  : MON_ERROR
*             MON_OK
*-------------------------------------------------------*/
typedef mon_status_t (*vmcall_event_handler_t)(const guest_vcpu_t *vcpu_id,
					       address_t *arg);


/*-------------------------------------------------------*
*  PURPOSE  : If CR0/CR3/CR4 access happen, this function
*             is called to report to the Handler and deal
*             with the access according to Handler's
*             response
*  ARGUMENTS: vcpu_id       (IN) -- Pointer of Guest
*                                   Virtual CPU
*             qualification (IN) -- IA32_VMX_EXIT_
*                                   QUALIFICATION
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*cr_access_event_handler_t)(const guest_vcpu_t *vcpu_id,
					       uint64_t qualification);


/*-------------------------------------------------------*
*  PURPOSE  : Report to Handler the DR Load access event.
*             According to the response, set up IB
*             dispatch or enable MTF.
*  ARGUMENTS: vcpu_id       (IN) -- Pointer of Guest
*                                   Virtual CPU
*             qualification (IN) -- IA32_VMX_EXIT_
*                                   QUALIFICATION
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*dr_load_event_handler_t)(const guest_vcpu_t *vcpu_id,
					     uint64_t qualification);


/*-------------------------------------------------------*
*  PURPOSE  : Report LDTR load access event to Handler.
*             Deal with the event according to Handler's
*             response, set up IB dispatch or enable MTF.
*  ARGUMENTS: vcpu_id         (IN) -- Pointer of Guest
*                                     Virtual CPU
*             qualification   (IN) -- IA32_VMX_EXIT_
*                                     QUALIFICATION
*             instruction_info(IN) -- IA32_VMX_VMCS_VM_
*                                     EXIT_INFO_
*                                     INSTRUCTION_INFO
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*ldtr_load_event_handler_t)(const guest_vcpu_t *vcpu_id,
					       uint64_t qualification,
					       uint32_t instruction_info);


/*-------------------------------------------------------*
*  PURPOSE  : Report GDTR/IDTR access events to Handler.
*             Deal with the event according to Handler's
*             response, set up IB dispatch or enable MTF.
*  ARGUMENTS: vcpu_id         (IN) -- Pointer of Guest
*                                     Virtual CPU
*             qualification   (IN) -- IA32_VMX_EXIT_
*                                     QUALIFICATION
*             instruction_info(IN) -- IA32_VMX_VMCS_VM_
*                                     EXIT_INFO_
*                                     INSTRUCTION_INFO
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*gdtr_idtr_access_event_handler_t)(const guest_vcpu_t *
						      vcpu_id,
						      uint64_t qualification,
						      uint32_t instruction_info);


/*-------------------------------------------------------*
*  PURPOSE  : Handler of MSR Read access, no monitoring
*             currently, just enable MTF
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*msr_read_event_handler_t)(const guest_vcpu_t *vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : Gets notified of mtf vmexits
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*mtf_vmexit_event_handler_t)(const guest_vcpu_t *vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : Check if dummy EPT is in use and all MTF
*             modes of given CPU is
*             MTF_TYPE_DATA_ALLOW.
*  ARGUMENTS: vcpu_id        (IN) -- Pointer of Guest
*                                    Virtual CPU
*             current_cpu_rip(IN) -- Current CPU RIP
*             vmexit_reason  (IN) -- VMEXIT reason
*  RETURNS  : TRUE
*             FALSE -- Dummy EPT is not in use, or MTF mode
*                      is not TYPE_DATA_ALLOW.
*-------------------------------------------------------*/
typedef boolean_t (*initial_vmexit_check_event_handler_t)(const guest_vcpu_t *
							  vcpu_id,
							  uint64_t
							  current_cpu_rip,
uint32_t vmexit_reason);


/*-------------------------------------------------------*
*  PURPOSE  : Single stepping check and disable MTF if
*             possible.
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*single_stepping_check_event_handler_t)(const guest_vcpu_t *
							   vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : Report the Halt instruction event to Handler
*             According the response from Handler, set up
*             IB dispatch or enable MTF
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*halt_instruction_event_handler_t)(const guest_vcpu_t *
						      vcpu_id);

/*-------------------------------------------------------*
*  PURPOSE  : Report the NMI event to Handler
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*build_nmi_event_handler_t)(const guest_vcpu_t *vcpu_id);

/*-------------------------------------------------------*
*  PURPOSE  : Report the log event to Handler
*             Ignore responses from handler
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             vector -- vector of re-injected NMI or typedefal
*                       interrupt
*  RETURNS  : NONE
*-------------------------------------------------------*/
typedef void (*log_event_handler_t)(const guest_vcpu_t *vcpu_id,
				    uint32_t vector);

/*-------------------------------------------------------*
*  PURPOSE  : Report the CPUID vmexit event to Handler
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             cpuid_params (IN) -- CPUID parameters
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
typedef boolean_t (*cpuid_vmexit_event_handler_t)(const guest_vcpu_t *vcpu_id,
						  uint64_t cpuid_params);

/*-------------------------------------------------------*
*  PURPOSE  : Report the MON Assert event to Plugin
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : Return the view index to switch to
*-------------------------------------------------------*/
typedef uint64_t (*mon_assert_event_handler_t)(const guest_vcpu_t *vcpu_id);

/*
 * Structure for xmon plugin event handlers registration
 * Plugin should initialize all unused handler pointers to NULL
 */

typedef struct {
	initialize_event_handler_t		initialize_event_handler;
	initialize_after_aps_started_event_handler_t
						initialize_after_aps_started_event_handler;
	ept_violation_event_handler_t		ept_violation_event_handler;
	msr_write_event_handler_t		msr_write_event_handler;
	io_access_event_handler_t		io_access_event_handler;
	fvs_set_active_view_event_handler_t
						fvs_set_active_view_event_handler;
	mon_teardown_event_handler_t		mon_teardown_event_handler;
	invalid_fvs_event_handler_t		invalid_fvs_event_handler;
	vmx_preemption_timer_event_handler_t
						vmx_preemption_timer_event_handler;
	vmcall_event_handler_t			vmcall_event_handler;
	cr_access_event_handler_t		cr_access_event_handler;
	dr_load_event_handler_t			dr_load_event_handler;
	ldtr_load_event_handler_t		ldtr_load_event_handler;
	gdtr_idtr_access_event_handler_t	gdtr_idtr_access_event_handler;
	msr_read_event_handler_t		msr_read_event_handler;
	mtf_vmexit_event_handler_t		mtf_vmexit_event_handler;
	initial_vmexit_check_event_handler_t
						initial_vmexit_check_event_handler;
	single_stepping_check_event_handler_t
						single_stepping_check_event_handler;
	halt_instruction_event_handler_t	halt_instruction_event_handler;
	build_nmi_event_handler_t		build_nmi_event_handler;
	log_event_handler_t			log_event_handler;
	cpuid_vmexit_event_handler_t		cpuid_vmexit_event_handler;
	mon_assert_event_handler_t		mon_assert_event_handler;
} xmon_event_handlers_t;

/*-------------------------------------------------------*
*
*  PURPOSE  : Plugin registers its own xmon event handlers
*  ARGUMENTS: plugin_handlers (INOUT) -- Pointer to the
*                       struct of xmon_event_handlers_t
*  RETURNS  : N/A
*-------------------------------------------------------*/
void plugin_initialize(xmon_event_handlers_t *plugin_handlers);


/* Utility functions for Guest Virtual CPU */

/*-------------------------------------------------------*
*  PURPOSE  : Get guest_vcpu_t directly from the scheduler
*  ARGUMENTS: N/A
*  RETURNS  : Pointer of Guest Virtual CPU
*-------------------------------------------------------*/
const guest_vcpu_t *xmon_get_guest_vcpu(void);


/* Utility functions for View operations */

/*-------------------------------------------------------*
*  PURPOSE  : Enable/disable views (EPT)
*             Also enables/disables unrestricted guest
*             mode, if necessary.
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE if EPT was enabled
*             FALSE if not enabled (not supported)
*-------------------------------------------------------*/
boolean_t xmon_enable_view(const guest_vcpu_t *vcpu_id, boolean_t enable);


/*-------------------------------------------------------*
*  PURPOSE  : Compute EPTP and invalidate the given view
*  ARGUMENTS: from (IN) -- CPU ID
*             arg  (IN) -- view_invalidation_data_t
*  RETURNS  : N/A
*-------------------------------------------------------*/
void xmon_invalidate_view(cpu_id_t from UNUSED, void *arg);


/*-------------------------------------------------------*
*  PURPOSE  : Recreate the given view
*  ARGUMENTS: guest_id       (IN) -- Guest ID
*             view           (IN) -- View Handle
*             eptp_list_index(IN) -- List Index of EPT
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_recreate_view(guest_id_t guest_id,
			     view_handle_t view,
			     uint64_t eptp_list_index);


/*-------------------------------------------------------*
*  PURPOSE  : Notify the MON about the modification in
*             the view
*  ARGUMENTS: from (IN) -- CPU ID
*             arg  (IN) -- Guest ID
*  RETURNS  : N/A
*-------------------------------------------------------*/
void xmon_notify_mon_about_view_recreation(cpu_id_t from UNUSED, void *arg);

/*-------------------------------------------------------*
*  PURPOSE  : Set the given view as the active view,
*             update the MON state on current processor
*             (GPM and EPT)
*  ARGUMENTS: vcpu_id   (IN) -- Pointer of Guest Virtual
*                               CPU.
*             view      (IN) -- View Handle. Function
*                               assumes valid input.
*             update_hw (IN) -- TRUE means to set the EPTP
*                               in the VMCS (Hardware);
*                               FALSE means don't update
*                               Hardware
*             eptp_list_index(IN) -- List Index of EPT
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_set_active_view(const guest_vcpu_t *vcpu_id,
			       view_handle_t view,
			       boolean_t update_hw,
			       uint64_t eptp_list_index);


/*-------------------------------------------------------*
*  PURPOSE  : Update the MON state on all processors to
*             use the given view GPM and EPT while
*             launching guest
*  ARGUMENTS: guest_id (IN) -- Guest ID
*             view     (IN) -- Given View Handle
*  RETURNS  : N/A
*-------------------------------------------------------*/
void xmon_set_mon_state_before_guest_launch(guest_id_t guest_id,
					    view_handle_t view);


/*-------------------------------------------------------*
*  PURPOSE  : Allocate memory and initialize a view
*  ARGUMENTS: N/A
*  RETURNS  : view_handle_t of the initialized view
*-------------------------------------------------------*/
view_handle_t xmon_initialize_view(void);


/*-------------------------------------------------------*
*  PURPOSE  : Create the given view
*  ARGUMENTS: guest_id       (IN) -- Guest ID
*             view           (IN) -- Given View Handle
*             override_perms (IN) -- TRUE to override the
*                                    permissions with the
*                                    argument perms;
*                                    FALSE to copy startup
*                                    GPM permissions
*             perms          (IN) -- Permissions to be set
*                                    if override_perms is
*                                    TRUE
*             eptp_list_index(IN) -- List Index of EPT
*  RETURNS  : N/A
*-------------------------------------------------------*/
void xmon_create_view(guest_id_t guest_id,
		      view_handle_t view,
		      boolean_t override_perms,
		      mam_attributes_t perms,
		      uint64_t eptp_list_index);


/*-------------------------------------------------------*
*  PURPOSE  : This function is used to create a view
*             from the passed-in view. No GPM will be
*             created in this function. The GPM field of
*             this copied view will point to the GPM of
*             source View.
*  ARGUMENTS: guest_id       (IN) -- Guest ID
*             dst_view       (OUT)-- The copy View Handle
*                                    (First time creation)
*                            (IN) -- In case of recreation
*             src_view       (IN) -- The view to be copied
*             original_perms (IN) -- TRUE to keep original
*                                    permissions of the
*                                    src_view;
*                                    FALSE, permissions
*                                    will be rwx
*             eptp_list_index(IN) -- List Index of EPT
*  RETURNS  : N/A
*-------------------------------------------------------*/
void xmon_copy_view(guest_id_t guest_id,
		    view_handle_t *dst_view,
		    view_handle_t src_view,
		    boolean_t original_perms,
		    uint64_t eptp_list_index);


/*-------------------------------------------------------*
*  PURPOSE  : Reset GPM for the given view to original
*             (startup) with RO permissions
*  ARGUMENTS: vcpu_id        (IN) -- Pointer of Guest
*                                    Virtual CPU.
*                                    Function assumes
*                                    valid input
*             view           (IN) -- View Handle. Function
*                                    Assumes valid
*                                    input.
*             eptp_list_index(IN) -- List Index of EPT
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_remove_view(const guest_vcpu_t *vcpu_id,
			   view_handle_t view,
			   uint64_t eptp_list_index);


/*-------------------------------------------------------*
*  PURPOSE  : Frees the memory allocated for the Views
*             (created using xmon_copy_view API)
*  ARGUMENTS: guest_id        (IN) -- Guest ID
*             view            (IN) -- View Handle
*             eptp_list_index (IN) -- List Index of EPT
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_remove_copied_view(guest_id_t guest_id,
				  view_handle_t view,
				  uint64_t eptp_list_index);


/*-------------------------------------------------------*
*  PURPOSE  : Update the given base_gpa with argument attr
*             in the given view
*  ARGUMENTS: vcpu_id        (IN) -- Pointer of Guest
*                                    Virtual CPU
*             view           (IN) -- View Handle
*             update_type    (IN) -- Update permissions or
*                                    add mapping to view
*             base_gpa       (IN) -- Given Guest Physical
*                                    Address
*             base_hpa       (IN) -- Given Host Physical
*                                    Address for new
*                                    mapping
*             attr           (IN) -- mam_attributes_t to
*                                    update with
*             eptp_list_index(IN) -- List Index of EPT
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_update_view(const guest_vcpu_t *vcpu_id,
			   view_handle_t view,
			   view_update_type_t update_type,
			   gpa_t base_gpa,
			   hpa_t base_hpa,
			   mam_attributes_t attr,
			   uint64_t eptp_list_index);


#ifdef DEBUG
/*-------------------------------------------------------*
*  PURPOSE  : Print all valid GPA->HPA mappings for the
*             given view's address space
*  ARGUMENTS: vcpu_id        (IN) -- Pointer of Guest
*                                    Virtual CPU
*             view           (IN) -- View Handle
*  RETURNS  : N/A
*-------------------------------------------------------*/
void view_print(const guest_vcpu_t *vcpu_id, view_handle_t view);
#endif


/* CPU event monitoring */

/*-------------------------------------------------------*
*  PURPOSE  : Register the MSR write access event to xmon.
*             Plugin would enable monitoring of write access
*             to this MSR.
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             msr_id  (IN) -- MSR ID
*  RETURNS  : MSR_ID_INVALID
*             MSR_REG_FAIL
*             MSR_REG_OK
*-------------------------------------------------------*/
msr_reg_status_t xmon_register_msr_write(const guest_vcpu_t *vcpu_id,
					 msr_id_t msr_id);


/*-------------------------------------------------------*
*  PURPOSE  : Unregister the MSR write event from MON.
*             Plugin would disable write access monitoring.
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             msr_id  (IN) -- MSR ID
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_unregister_msr_write(const guest_vcpu_t *vcpu_id,
				    msr_id_t msr_id);



/*-------------------------------------------------------*
*  PURPOSE  : Register the IO port to enable
*             monitoring of IO access to this port
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             port_id (IN) -- IO port ID
*  RETURNS  : TRUE  -- register io vmexit handler successfully.
*             FALSE -- failed to register io vmexit handler.
*-------------------------------------------------------*/
boolean_t xmon_register_io_access(const guest_vcpu_t *vcpu_id,
				  io_port_id_t port_id);



/*-------------------------------------------------------*
*  PURPOSE  : Unregister the IO port to disable
*             monitoring of IO access to this port
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             port_id (IN) -- IO port ID
*  RETURNS  : TRUE  -- unregister io vmexit handler successfully.
*             FALSE -- failed to unregister io vmexit handler.
*-------------------------------------------------------*/
boolean_t xmon_unregister_io_access(const guest_vcpu_t *vcpu_id,
				    io_port_id_t port_id);


/* Address translation (dependency on GPM) */

/*-------------------------------------------------------*
*  PURPOSE  : Convert GPA to HPA
*  ARGUMENTS: vcpu_id   (IN) -- Pointer of Guest Virtual
*                               CPU
*             view      (IN) -- View Handle
*             gpa       (IN) -- Guest Physical Address
*             hpa       (OUT)-- Pointer of Host Virtual
*                               Address
*             hpa_attrs (OUT)-- Pointer of MAM Attributes
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_gpa_to_hpa(const guest_vcpu_t *vcpu_id,
			  view_handle_t view,
			  gpa_t gpa,
			  hpa_t *hpa,
			  mam_attributes_t *hpa_attrs);


/*-------------------------------------------------------*
*  PURPOSE  : Convert HPA to GPA
*  ARGUMENTS: vcpu_id(IN) -- Pointer of Guest Virtual CPU
*             view   (IN) -- View Handle
*             hpa    (IN) -- Host Physical Address
*             gpa    (OUT)-- Pointer of Guest Virtual
*                            Address
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_hpa_to_gpa(const guest_vcpu_t *vcpu_id,
			  view_handle_t view,
			  hpa_t hpa,
			  gpa_t *gpa);


/*-------------------------------------------------------*
*  PURPOSE  : Check whether given address is in MMIO range
*  ARGUMENTS: view (IN) -- View Handle
*             gpa  (IN) -- Guest Physical Address
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_is_mmio_address(view_handle_t view, gpa_t gpa);


/* WRAPPER FUNCTIONS (dependency on EPT) */

/*-------------------------------------------------------*
*  PURPOSE  : Check if given cpu is in non paged mode
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE  -- in non paged mode
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_is_cpu_in_non_paged_mode(const guest_vcpu_t *vcpu_id);


/* WRAPPER FUNCTIONS (dependency on GCPU) */

/*-------------------------------------------------------*
*  PURPOSE  : Convert GVA to GPA
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             gva     (IN) -- Guest Virtual Address
*             gpa     (OUT)-- Pointer of Host Virtual
*                             Address
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_gva_to_gpa(const guest_vcpu_t *vcpu_id, gva_t gva, gpa_t *gpa);

/*-------------------------------------------------------*
*  PURPOSE  : Convert GVA to GPA for given page table
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             gva     (IN) -- Guest Virtual Address
*             cr3     (IN) -- CR3 value to use in page table walk
*             gpa     (OUT)-- Pointer of Host Virtual
*                             Address
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_gva_to_gpa_from_cr3(const guest_vcpu_t *vcpu_id,
				   gva_t gva,
				   uint64_t cr3,
				   gpa_t *gpa);

/*-------------------------------------------------------*
*  PURPOSE  : Convert HPA to HVA
*  ARGUMENTS: hpa (IN) -- Host Physical Address
*             hva (OUT)-- Pointer of Host Virtual Address
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_hpa_to_hva(hpa_t hpa, hva_t *hva);


/*-------------------------------------------------------*
*  PURPOSE  : Convert HVA to HPA
*  ARGUMENTS: hva (IN) -- Pointer of Host Virtual Address
*             hpa (OUT)-- Host Physical Address
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_hva_to_hpa(hva_t hva, hpa_t *hpa);


/* Fast-view-switch operations */

/*-------------------------------------------------------*
*  PURPOSE  : Check if Fast View Switch enabled
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE  -- FVS is enabled
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_is_fvs_enabled(const guest_vcpu_t *vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : Enable Fast View Switch
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE  -- Enable successfully
*             FALSE
*-------------------------------------------------------*/
void xmon_enable_fvs(const guest_vcpu_t *vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : Disable Fast View Switch
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE  -- Disable successfully
*             FALSE
*-------------------------------------------------------*/
void xmon_disable_fvs(const guest_vcpu_t *vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : Enable/disable FVS on current core
*  ARGUMENTS: vcpu_id (IN) -- Pointer to Guest Virtual CPU
*  RETURNS  : N/A
*-------------------------------------------------------*/
void xmon_enable_fvs_single_core(const guest_vcpu_t *vcpu_id, boolean_t enable);


/*-------------------------------------------------------*
*  PURPOSE  : Get the address of the HPA list, in which
*             each HPA is the address of eptp list page
*             (1 per core).
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : Host physical address of the HPA list for
*             all eptp list pages
*-------------------------------------------------------*/
hpa_t *xmon_get_eptp_list_paddress(const guest_vcpu_t *vcpu_id);

/*-------------------------------------------------------*
*  PURPOSE  : Add eptp of given view and core to eptp list
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             view (IN) -- Pointer of Guest_VIEW
*             eptp_list_index (IN) -- Index of eptp list
*  RETURNS  : TRUE/FALSE
*-------------------------------------------------------*/
boolean_t xmon_add_eptp_entry_single_core(const guest_vcpu_t *vcpu_id,
					  view_handle_t view,
					  uint64_t eptp_list_index);

/*-------------------------------------------------------*
*  PURPOSE  : Delete eptp of given view and core from eptp list
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             eptp_list_index (IN) -- Index of eptp list
*  RETURNS  : TRUE/FALSE
*-------------------------------------------------------*/
boolean_t xmon_delete_eptp_entry_single_core(const guest_vcpu_t *vcpu_id,
					     uint64_t eptp_list_index);

/*-------------------------------------------------------*
*  PURPOSE  : Delete eptp of given view from eptp list for all cores
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             eptp_list_index (IN) -- Index of eptp list
*  RETURNS  : TRUE/FALSE
*-------------------------------------------------------*/
boolean_t xmon_delete_entry_from_eptp_list_all_cores(
	const guest_vcpu_t *vcpu_id,
	uint64_t eptp_list_index);

/*-------------------------------------------------------*
*  PURPOSE  : Get ept address for view handle passed in
*  ARGUMENTS: ept_addr (IN) -- Value to be filled in
*             view (IN) -- Pointer of Guest_VIEW
*  RETURNS  : TRUE/FALSE
*-------------------------------------------------------*/
boolean_t xmon_get_ept_addr(view_handle_t view, uint64_t *ept_addr);

/*-------------------------------------------------------*
*  PURPOSE  : Check if #VE support in HW
*  ARGUMENTS: N/A
*  RETURNS  : TRUE  -- HW #VE is support
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_is_hw_ve_supported(void);

/*-------------------------------------------------------*
*  PURPOSE  : Check if #VE enabled
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE  -- #VE is enabled
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_is_ve_enabled(const guest_vcpu_t *vcpu_id);

/*-------------------------------------------------------*
*  PURPOSE  : Check if hpa is used by other CPUs in previous enables
*  ARGUMENTS: guest_id (IN) -- Guest ID
*             guest_cpu_id (IN) -- Guest CPU ID
*             HPA (IN) -- hpa
*             enable (IN) - #VE enable/disable flag
*  RETURNS  : TRUE  -- hpa is saved
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_ve_update_hpa(guest_id_t guest_id,
			     cpu_id_t guest_cpu_id,
			     hpa_t hpa,
			     uint32_t enable);

/*-------------------------------------------------------*
*  PURPOSE  : Enable #VE
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : N/A
*-------------------------------------------------------*/
void xmon_ve_enable(const guest_vcpu_t *vcpu_id);

/*-------------------------------------------------------*
*  PURPOSE  : Disable #VE
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : N/A
*-------------------------------------------------------*/
void xmon_ve_disable(const guest_vcpu_t *vcpu_id);

/*-------------------------------------------------------*
*  PURPOSE  : Handle SW #VE
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             qualification (IN) -- ept qualification
*             gla (IN) -- guest linear address
*             gpa (IN) -- guest physical address
*             view (IN) -- active view
*  RETURNS  : TRUE  -- SW #VE injected
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_handle_sw_ve(const guest_vcpu_t *vcpu_id,
			    uint64_t qualification,
			    uint64_t gla,
			    uint64_t gpa,
			    uint64_t view);


/* Other utility functions */

/*-------------------------------------------------------*
*  PURPOSE  : Inject an Invalid Opcode Exception or
*             General Protection Exception
*  ARGUMENTS: vcpu_id        (IN)  -- Pointer of Guest
*                                     Virtual CPU
*             exception_type (IN)  -- Currently only
*                                     support UD and GP
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_inject_exception(const guest_vcpu_t *vcpu_id,
				exception_type_t exception_type);


/*-------------------------------------------------------*
*  PURPOSE  : Check x_only bit of EPT capabilities
*  ARGUMENTS: N/A
*  RETURNS  : TRUE  -- Execute only is supported
*             FALSE -- Not supported
*-------------------------------------------------------*/
boolean_t xmon_is_execute_only_supported(void);


/*-------------------------------------------------------*
*  PURPOSE  : Check UG support
*  ARGUMENTS: N/A
*  RETURNS  : TRUE  -- UG is supported
*             FALSE -- Not supported
*-------------------------------------------------------*/
boolean_t xmon_is_unrestricted_guest_supported(void);


/*-------------------------------------------------------*
*  PURPOSE  : Get the value of given Guest State ID
*  ARGUMENTS: vcpu_id       (IN) -- Pointer of Guest Virtual
*                                 CPU
*             guest_state_id(IN) -- Guest State ID
*             value         (OUT)-- Pointer of the Guest
*                                 State value
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_get_vmcs_guest_state(const guest_vcpu_t *vcpu_id,
				    mon_guest_state_t guest_state_id,
				    mon_guest_state_value_t *value);


/*-------------------------------------------------------*
*  PURPOSE  : Set the value of given Guest State ID to the
*             given value
*  ARGUMENTS: vcpu_id       (IN) -- Pointer of Guest Virtual
*                                 CPU
*             guest_state_id(IN) -- Guest State ID
*             value         (IN) -- Given Guest State value
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_set_vmcs_guest_state(const guest_vcpu_t *vcpu_id,
				    mon_guest_state_t guest_state_id,
				    mon_guest_state_value_t value);


/*-------------------------------------------------------*
*  PURPOSE  : Get the value of given Control State ID
*  ARGUMENTS: vcpu_id         (IN) -- Pointer of Guest
*                                   Virtual CPU
*             control_state_id(IN) -- Control State ID
*             value           (OUT)-- Pointer of the Control
*                                   State value
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_get_vmcs_control_state(const guest_vcpu_t *vcpu_id,
				      mon_control_state_t control_state_id,
				      mon_controls_t *value);


/*-------------------------------------------------------*
*  PURPOSE  : Set the value of given Control State ID to
*             the given value
*  ARGUMENTS: vcpu_id         (IN) -- Pointer of Guest
*                                   Virtual CPU
*             control_state_id(IN) -- Control State ID
*             value           (IN) -- Pointer of the Given
*                                   Control State value
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_set_vmcs_control_state(const guest_vcpu_t *vcpu_id,
				      mon_control_state_t control_state_id,
				      mon_controls_t *value);


/*-------------------------------------------------------*
*  PURPOSE  : Get CR0 minimal settings, that are one time
*             calculated at boot, enforce 1 for each bit
*             set
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : Value of CR0 minimal 1 settings
*-------------------------------------------------------*/
uint64_t xmon_get_cr0_minimal_settings(const guest_vcpu_t *vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : Get CR4 minimal settings, that are one time
*             calculated at boot, enforce 1 for each bit
*             set
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : Value of CR4 minimal 1 settings
*-------------------------------------------------------*/
uint64_t xmon_get_cr4_minimal_settings(const guest_vcpu_t *vcpu_id);


/*-------------------------------------------------------*
*  PURPOSE  : find out whether VT-d is available
*  ARGUMENTS: void
*  RETURNS  : TURE -- VT-d is available
*             FALSE --VT-d is not available
*-------------------------------------------------------*/
boolean_t xmon_is_vtd_available(void);

/*-------------------------------------------------------*
*  PURPOSE  : flush iotlb after updating VT-d map
*  ARGUMENTS: void
*  RETURNS  : void
*
*  BACKGROUNDS:
*      1. if flush device tlb page by page, and when guest software calls
*  the APIs (e.g. addpages_ib_ex()) with so many pages, then it
*  takes a long time, and causes the system 0x101 (watchdog timeout)
*  BSOD.
*      2. we also measured the time of flushing global TLB and flushing
*  page TLB, they are using almost the same time.
*      3. we understood that "flushing global TLB" will cause the DMA
*  operations taking longer time to complete because they cannot use
*  the cached TLBs at the time of DMA operations. However, this is
*  "one time only" impact when calling those Plugin APIs, assumed that
*  IBAgent won't call the Plugin APIs to update permissions very
*  frequently at system run time.
*-------------------------------------------------------*/
void xmon_inv_iotlb_global(void);

/*-------------------------------------------------------*
*  PURPOSE  : Block DMA write for given gpa and size
*  ARGUMENTS: gpa (IN) -- protected guest physical address
*             size (IN) -- size of protected area in bytes
*  RETURNS  : TURE -- update vtd mapping successfully
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_dma_block_write(address_t gpa, uint32_t size);

/*-------------------------------------------------------*
*  PURPOSE  : Restore DMA write for given gpa and size
*  ARGUMENTS: gpa (IN) -- target guest physical address
*             size (IN) -- size of protected area in bytes
*  RETURNS  : TURE -- update vtd mapping successfully
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_dma_unblock_write(address_t gpa, uint32_t size);

/*-------------------------------------------------------*
*  PURPOSE  : Redirect DMA access to a dummy page for
*             given gpa and size
*  ARGUMENTS: gpa (IN) -- target guest physical address
*             size (IN) -- size of protected area in bytes
*  RETURNS  : TURE -- update vtd mapping successfully
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_dma_remapping(address_t gpa, uint32_t size);

/*-------------------------------------------------------*
*  PURPOSE  : Restore DMA mapping for given gpa and size
*  ARGUMENTS: gpa (IN) -- target guest physical address
*             size (IN) -- size of protected area in bytes
*  RETURNS  : TURE -- update vtd mapping successfully
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_dma_restore_mapping(address_t gpa, uint32_t size);

/*-------------------------------------------------------*
*  PURPOSE  : Get VMEXIT reason, qualification and GVA
*  ARGUMENTS: reason (OUT) -- VMEXIT reason
*  RETURNS  : TRUE  -- successful
*             FALSE
*-------------------------------------------------------*/
boolean_t xmon_get_vmexit_reason(const guest_vcpu_t *vcpu_id,
				 vmexit_reason_t *reason);

void xmon_register_handlers(xmon_event_handlers_t *plugin_handlers);

#endif /* _XMON_API_H */
