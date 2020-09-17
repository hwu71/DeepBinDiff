#!/bin/bash -eu

# build all benchmarks using ./build-benchmark script

root_dir=/home/elaine_whw/Codes/DeepBinDiff


bench_dir=/home/elaine_whw/Codes/mram-patches/benchmarks
cd $bench_dir

for benchmark in *; do
    cd $bench_dir
    if [[ ! -d $benchmark ]]; then continue; fi
    
    # need to have CWD as the root for the ./build-benchmark.sh script
    cd $root_dir
	if [[ ! -e $root_dir/log/$benchmark.txt ]]; then 
		echo "Building $benchmark"
		./test_benchmark.sh $benchmark
    else
		echo "Skipping $benchmark..."
	fi
  
done

cd ..
 
