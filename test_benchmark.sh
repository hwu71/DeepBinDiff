#!/bin/bash -eu

SCRIPT=`basename ${BASH_SOURCE[0]}`

#Help function
function HELP {
  echo -e "Usage: $SCRIPT [benchmark-name]"
  exit 1
}

while getopts lh FLAG; do
    case $FLAG in
        h)
            HELP
            ;;
        \?) #unrecognized option - show help
            echo -e \\n"Option -${BOLD}$OPTARG${OFF} not allowed."
            HELP
            ;;
    esac
done

#shift $((OPTIND -1))

benchmark=$1 #; shift 
target=$2
original_path=/home/hongwei/Desktop/Codes/mram-patches/benchmarks/${benchmark}/build/original/${target}
patched_path=/home/hongwei/Desktop/Codes/mram-patches/benchmarks/${benchmark}/build/patched/${target}
echo ${original_path}
echo ${patched_path}

#filesize=`ls -l ${original_path} | awk '{ print $5 }'`
#maxsize=$((1024*10))
if [[ -d output/${benchmark} ]]; then
	echo "Skipping ${benchmark}, already done..."
else
	if [[ ! -d ${original_path%/*} || ! -d ${patched_path%/*} ]]; then 
		echo "Incorrect $benchmark dir, skipping..."
	elif [[ ${benchmark} == dillo* || ${benchmark} == display* || ${benchmark} == dnsmasq* ]]; then
		# can use "${benchmark%%-*} == dillo" as well
		echo "Skipping ${benchmark} for unsupported opcode..."
		
	else
		#echo "python3 src/deepbindiff.py --input1 ${original_path} --input2 ${patched_path}/* --outputDir output/${benchmark}/* > log/${benchmark}.txt"
		echo "Running ${benchmark} with DeepBinDiff..."
		python3 src/deepbindiff.py --input1 ${original_path} --input2 ${patched_path} --outputDir output/${benchmark} 
		echo "Running ${benchmark} with Angr..."
		python3 src/test_bindiff.py --input1 ${original_path} --input2 ${patched_path} --outputDir output/${benchmark} 
		echo "Comparing b1.diff..."
		diff output/${benchmark}/b1_matched_pairs_within_functions_angr output/${benchmark}/b1_matched_pairs_within_functions_deepbindiff > output/${benchmark}/b1.diff
		echo "Comparing b2.diff..."
		diff output/${benchmark}/b2_matched_pairs_within_functions_angr output/${benchmark}/b2_matched_pairs_within_functions_deepbindiff > output/${benchmark}/b2.diff
		#echo "Correct dir, and acceptable binaries, executing..."
	fi

fi

