package beater

import (
	"math"

	"github.com/breml/bpfutils"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/google/gopacket/pcap"

	"golang.org/x/net/bpf"
)

func getSamplerBpf(sampleRate int, snapshotLen int32) []pcap.BPFInstruction {
	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Get a 32-bit random number from the Linux kernel.
		bpf.LoadExtension{Num: bpf.ExtRand},
		// if random number is in the first share of MaxUint32 / sampleRate
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: math.MaxUint32 / uint32(sampleRate), SkipTrue: 1},
		// Capture.
		bpf.RetConstant{Val: uint32(snapshotLen)},
		// Ignore.
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		// BPF asm instructions are static, this should never happen
		logp.WTF(err.Error())
	}
	return bpfutils.ToPcapBPFInstructions(bpf)
}
