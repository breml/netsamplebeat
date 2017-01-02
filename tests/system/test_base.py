from netsamplebeat import BaseTest

import os


class Test(BaseTest):

    def test_base(self):
        """
        Basic test with exiting Netsamplebeat normally
        """
        self.render_config_template(
                path=os.path.abspath(self.working_dir) + "/log/*"
        )

        netsamplebeat_proc = self.start_beat(extra_args=["-I", "pcaps/icmp/icmp4_ping.pcap", "-e"])
        self.wait_until( lambda: self.log_contains("netsamplebeat is running"))
        exit_code = netsamplebeat_proc.kill_and_wait()
        assert exit_code == 0
