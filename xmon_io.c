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
#include "file_codes.h"
#define MON_DEADLOOP()          MON_DEADLOOP_LOG(XMON_IO_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(XMON_IO_C, __condition)
#include "xmon_internal.h"
#include "guest_cpu.h"
#include "guest.h"
#include "vmexit_io.h"



/* this io handler will get called once the monitored IO is accessed by guest
 * such event will be reported to plugin. */
static
boolean_t xmon_io_port_handler(
	guest_cpu_handle_t gcpu,
	io_port_id_t port_id,
	unsigned port_size,
	rw_access_t access,
	boolean_t string_intr,                          /* ins/outs */
	boolean_t rep_prefix,                           /* rep */
	uint32_t rep_count,
	void *p_value,
	void *context UNUSED
	)
{
	const guest_vcpu_t *vcpu_id = NULL;
	boolean_t status = FALSE, is_mon_owner;
	uint64_t gva_ptr = 0;


	MON_ASSERT(gcpu);
	vcpu_id = get_guest_vcpu_from_gcpu(gcpu);
	if (!vcpu_id) {
		return status;
	}
	set_xmon_state(gcpu, vcpu_id);
	/* TODO: fix MON/plugin io port monitor conflict. */
	is_mon_owner = FALSE;

	/* Report value gva ptr only for INS/OUTS string access. */
	gva_ptr = (string_intr == TRUE) ? (uint64_t)p_value : 0;

	MON_LOG(mask_xmon_api, level_trace,
		"Report IO access Instruction to plugin\n");

	if (!g_plugin_handlers.io_access_event_handler) {
		return TRUE;
	}

	/* Report to Handler, enable MTF if ALLOW */
	status = g_plugin_handlers.io_access_event_handler(vcpu_id,
		port_id,
		(uint16_t)port_size,
		(access == READ_ACCESS) ? TRUE : FALSE,
		string_intr,
		rep_prefix,
		rep_count,
		is_mon_owner,
		gva_ptr);

	return status;
}


/*
 * enable IO monitor,and set callback xmon_io_port_handler() when io vmexit happens.
 */
boolean_t xmon_register_io_access(const guest_vcpu_t *vcpu_id,
				  io_port_id_t port_id)
{
	MON_ASSERT(vcpu_id);

	if (mon_io_vmexit_handler_register(vcpu_id->guest_id, port_id,
		    xmon_io_port_handler, NULL) != MON_OK) {
		MON_LOG(mask_xmon_api,
			level_error,
			"%s: Error - mon_io_vmexit_handler_register failed, port =%d\n",
			__FUNCTION__,
			port_id);
		return FALSE;
	}

	return TRUE;
}


/*
 * Disable IO monitor,and remove callback function.
 */
boolean_t xmon_unregister_io_access(const guest_vcpu_t *vcpu_id,
				    io_port_id_t port_id)
{
	MON_ASSERT(vcpu_id);

	if (mon_io_vmexit_handler_unregister(vcpu_id->guest_id,
		    port_id) != MON_OK) {
		MON_LOG(mask_xmon_api,
			level_error,
			"%s: Error - mon_io_vmexit_handler_unregister failed, port =%d\n",
			__FUNCTION__,
			port_id);
		return FALSE;
	}


	return TRUE;
}

