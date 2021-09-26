CREATE DATABASE IF NOT EXISTS lmp;
use lmp;
drop table if exists performance_index;
CREATE TABLE if NOT EXISTS performance_index (
    id int(11) AUTO_INCREMENT PRIMARY KEY COMMENT '主键',
    plugin_name varchar(30) NOT NULL unique COMMENT '指标名',
    plugin_type varchar(10) NOT NULL COMMENT '指标类型',
    exec_path varchar(50) NOT NULL COMMENT '指标执行路径',
    instruction varchar(100) COMMENT '指标说明',
    state int NOT NULL COMMENT '状态'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("containerNet", "bcc", "./plugins/ContainerNet.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("cpuUtilize", "bcc", "./plugins/cpuutilize.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("hardDiskReadWriteTime", "bcc", "./plugins/harddiskreadwritetime.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("irq", "bcc", "./plugins/irq.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("memUsage", "bcc", "./plugins/memusage.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("netLatency", "bcc", "./plugins/netlatency.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("pickNext", "bcc", "./plugins/picknext.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("taskSwitch", "bcc", "./plugins/taskswitch.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("vfsStat", "bcc", "./plugins/vfsstat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("waitingQueueLength", "bcc", "./plugins/waitingqueuelength.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("oomkill", "bcc", "./plugins/oomkill.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("runqslower", "bcc", "./plugins/runqslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("slabratetop", "bcc", "./plugins/slabratetop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("memleak", "bcc", "./plugins/memleak.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("shmsnoop", "bcc", "./plugins/shmsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("drsnoop", "bcc", "./plugins/drsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("cachetop", "bcc", "./plugins/cachetop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("filetop", "bcc", "./plugins/filetop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("runqlat", "bcc", "./plugins/runqlat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("softirqs", "bcc", "./plugins/softirqs.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("cpudist", "bcc", "./plugins/cpudist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("sofdsnoop", "bcc", "./plugins/sofdsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("filelife", "bcc", "./plugins/filelife.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("cachestat", "bcc", "./plugins/cachestat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("dcstat", "bcc", "./plugins/dcstat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("dcsnoop", "bcc", "./plugins/dcsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("fileslower", "bcc", "./plugins/fileslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("vfscount", "bcc", "./plugins/vfscount.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("mountsnoop", "bcc", "./plugins/mountsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("mdflush", "bcc", "./plugins/mdflush.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("biotop", "bcc", "./plugins/biotop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("biosnoop", "bcc", "./plugins/biosnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("ext4slower", "bcc", "./plugins/ext4slower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcptop", "bcc", "./plugins/tcptop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcplife", "bcc", "./plugins/tcplife.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcptracer", "bcc", "./plugins/tcptracer.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpconnect", "bcc", "./plugins/tcpconnect.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpconnlat", "bcc", "./plugins/tcpconnlat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpretrans", "bcc", "./plugins/tcpretrans.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpsubnet", "bcc", "./plugins/tcpsubnet.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpdrop", "bcc", "./plugins/tcpdrop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("btrfsdist", "bcc", "./plugins/btrfsdist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("btrfsslower", "bcc", "./plugins/btrfsslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("xfsslower", "bcc", "./plugins/xfsslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("nfsslower", "bcc", "./plugins/nfsslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("zfsslower", "bcc", "./plugins/zfsslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("zfsdist", "bcc", "./plugins/zfsdist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("nfsdist", "bcc", "./plugins/nfsdist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("xfsdist", "bcc", "./plugins/xfsdist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("ext4dist", "bcc", "./plugins/ext4dist.py", "empty", 0);
