vlib ../modelsim/work
vmap work ../modelsim/work

vlog -sv generic/typedefs.sv
vlog -sv parser/parser_typedefs.sv
vlog -sv generic/protocols_typedefs.sv
vlog -sv tcp_reassembly/tcp_reassembly_typedefs.sv
vlog -sv hash/hash_typedefs.sv

vlog -sv generic/channels.sv

vlog -sv parser/parser.sv
vlog -sv tcp_reassembly/tcp_reassembly.sv
vlog -sv hash/hash.sv
vlog -sv snort_top/snort_top.sv

vlog -sv parser/parser_tb.sv
vlog -sv hash/hash_tb.sv
vlog -sv snort_top/snort_top_tb.sv

#vsim hash_tb
#vsim parser_tb
vsim snort_top_tb

run 10000
