package monitor

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/k8s"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/perf/net"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/tools"
)

func NewMonitorAllCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "all",
		Short:   "Monitor sidecar by all provided tools.",
		Long:    "",
		Example: "pmoas monitor all --pod sidecar-demo",
		PreRunE: preRunMonitor,
		RunE: func(cmd *cobra.Command, args []string) error {
			sockOpsRedirect()

			sidecarProcesses, serviceProcesses, err := k8s.GetSidecarAndServiceProcess(kubeconfig, nodeName, nameSpace, podName)
			if err != nil {
				fmt.Printf("[ERROR] Got err: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("[FINISHED] Get sidecar processes '%s'\n", sidecarProcesses)
			fmt.Printf("[FINISHED] Get service processes '%s'\n", serviceProcesses)

			var sidecarPid []int
			var servicePid []int
			var portList = []int{15006, 9080, 80, 8000}
			for i := 0; i < len(sidecarProcesses); i++ {
				sidecarPid = append(sidecarPid, int(sidecarProcesses[i].Pid))
			}
			for i := 0; i < len(serviceProcesses); i++ {
				servicePid = append(servicePid, int(serviceProcesses[i].Pid))
			}

			go net.GetRequestOverSidecarEvent(sidecarPid, servicePid, portList, podName)

			var pidList []int
			pidList = append(pidList, sidecarPid...)
			pidList = append(pidList, servicePid...)

			targetPod, err := tools.LocateTargetPod(tools.GetDefaultKubeConfig(), podName, nameSpace)

			so := net.SidecarOpt{
				SidecarPort: 8000,
				ServicePort: 80,
				LocalIP:     "127.0.0.1", // for Envoy, 127.0.0.6
				PodIp:       targetPod.Status.PodIP,
				NodeIp:      targetPod.Status.HostIP,
			}

			go net.GetKernelNetworkEvent(pidList, so, podName)

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, os.Kill)
			<-sig

			return nil
		},
	}

	return cmd
}
