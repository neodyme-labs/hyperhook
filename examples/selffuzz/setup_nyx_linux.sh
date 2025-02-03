mode=$1

python3 "../../../LibAFL/libafl_nyx/packer/packer/nyx_packer.py" \
    ./target/x86_64-unknown-linux-gnu/$mode/selffuzz \
    /tmp/selffuzz_linux \
    afl \
    processor_trace \
    -args "/tmp/input" \
    -file "/tmp/input" \
    --fast_reload_mode \
    --purge || exit

python3 ../../../LibAFL/libafl_nyx/packer/packer/nyx_config_gen.py /tmp/selffuzz_linux/ Kernel || exit