package ProcessMeasure

import (
	"fmt"
	"os"
	"time"

	"github.com/shirou/gopsutil/process"
)

func GetProcStatus(nameCrypt string, pharse string, p *process.Process, stop chan bool) {
	start := time.Now()
	fo_metric, _ := os.OpenFile(nameCrypt+"_metric.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	fo_time, _ := os.OpenFile(nameCrypt+"_running_time.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer fo_metric.Close()
	defer fo_time.Close()
	for {
		select {
		case <-stop:
			close(stop)
			fo_time.WriteString("Time " + pharse + " : " + fmt.Sprint(time.Since(start)) + "\n")
			return
		default:
			{
				c, _ := p.CPUPercent()
				m, _ := p.MemoryPercent()
				fo_metric.WriteString(fmt.Sprintf("CPU: %v  Memory: %v \n", c, m))
			}
		}
		time.Sleep(time.Microsecond * 280)
	}
}
