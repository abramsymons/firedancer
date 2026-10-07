ifdef FD_HAS_HOSTED
$(call add-hdrs,vseq_block.h vseq_sched.h vseq_node.h vseq_mesh.h vseq_ledger.h vseq_proof.h vseq_history.h vseq_client.h)
$(call add-objs,vseq_block vseq_sched vseq_node vseq_mesh vseq_ledger vseq_proof vseq_history,fd_vseq)
$(call make-bin,vseqd,vseqd,fd_vseq fd_choreo fd_waltz fd_tls fd_ballet fd_util)
$(call make-unit-test,test_vseq_sim,test_vseq_sim,fd_vseq fd_choreo fd_ballet fd_util)
$(call make-unit-test,test_vseq_ledger,test_vseq_ledger,fd_vseq fd_choreo fd_ballet fd_util)
$(call run-unit-test,test_vseq_ledger)
$(call make-fuzz-test,fuzz_vseq,fuzz_vseq,fd_vseq fd_choreo fd_ballet fd_util)

# Client library for the SDKs (Python loads it with ctypes)
VSEQ_CLIENT_FLAGS:=-Wl,--version-script=src/app/vseq/libvseq_client.map
$(call make-shared,libvseq_client.so,vseq_client,fd_vseq fd_choreo fd_ballet fd_util,$(VSEQ_CLIENT_FLAGS))
endif
