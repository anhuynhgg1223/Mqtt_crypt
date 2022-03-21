package ProcessMeasure

import (
	"fmt"
	"os"

	"github.com/shirou/gopsutil/process"
)

func GetProcStatus(place string, p *process.Process, stop chan bool) {
	fo, err := os.OpenFile(place+"_Output.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic("panik!")
	}
	fo.WriteString(place + " Metric Data (%): \n")
	defer fo.Close()
	for {
		select {
		case <-stop:
			close(stop)
			return
		default:
			{
				c, _ := p.CPUPercent()
				m, _ := p.MemoryPercent()
				fo.WriteString(fmt.Sprintf("CPU: %v  Memory: %v \n", c, m))
			}
		}
	}
}
