"""Unit tests for step-7c parsers: filesystem_suspicious and live_state."""

from __future__ import annotations

from datetime import UTC, datetime

from conftest import make_mini_evidence

from linuxdfir.ingest import Evidence
from linuxdfir.parsers import filesystem_suspicious, live_state


def _parse(parser, tmp_path, files, member):
    root = make_mini_evidence(tmp_path / "mini", files=files)
    with Evidence.open(root) as evidence:
        return list(parser.parse_member(evidence, member))


# ------------------------------------------------------ filesystem_suspicious


class TestFilesystemSuspicious:
    def test_suid_row_parses_fields(self, tmp_path):
        blob = (
            b"path\tmode\tuid\tgid\tsize\tmtime_utc\tflags\ttype\n"
            b"/usr/local/bin/evil\t0o4755\t0\t0\t12345\t2026-01-02T03:15:00Z\tsuid\tfile\n"
        )
        events = _parse(
            filesystem_suspicious, tmp_path,
            {"triage/suid_sgid.txt": blob}, "evidence/triage/suid_sgid.txt",
        )
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "suid_sgid_file"
        assert event.timestamp_utc == datetime(2026, 1, 2, 3, 15, 0, tzinfo=UTC)
        assert "path=/usr/local/bin/evil" in event.message
        assert "mode=0o4755" in event.message
        assert "flags=suid" in event.message
        fields = filesystem_suspicious.parse_fs_message(event.message)
        assert fields is not None
        assert fields["uid"] == "0" and fields["type"] == "file"

    def test_hidden_files_event_type(self, tmp_path):
        blob = (
            b"path\ttype\tmode\tuid\tgid\tsize\tmtime_utc\n"
            b"/root/.bashrc.bak\tfile\t0o644\t0\t0\t42\t2026-01-02T01:00:00Z\n"
        )
        events = _parse(
            filesystem_suspicious, tmp_path,
            {"triage/hidden_files.txt": blob}, "evidence/triage/hidden_files.txt",
        )
        assert events[0].event_type == "hidden_file"
        assert "path=/root/.bashrc.bak" in events[0].message

    def test_recent_files_directories_kept(self, tmp_path):
        blob = (
            b"path\ttype\tmode\tuid\tgid\tsize\tmtime_utc\tctime_utc\tatime_utc\n"
            b"/etc/cron.d\tdir\t0o755\t0\t0\t3\t2026-01-02T05:00:00Z"
            b"\t2026-01-02T05:00:00Z\t2026-01-02T05:00:00Z\n"
            b"/etc/cron.d/evil\tfile\t0o644\t0\t0\t88\t2026-01-02T04:30:00Z"
            b"\t2026-01-02T04:30:00Z\t2026-01-02T04:30:00Z\n"
        )
        events = _parse(
            filesystem_suspicious, tmp_path,
            {"triage/recent_files.txt": blob}, "evidence/triage/recent_files.txt",
        )
        assert len(events) == 2
        assert all(e.event_type == "recent_file" for e in events)
        assert "type=dir" in events[0].message
        assert "path=/etc/cron.d/evil" in events[1].message

    def test_tmp_listing_elf_tag_when_content_is_elf(self, tmp_path):
        header = (
            b"path\ttype\tmode\tuid\tgid\tsize\tmtime_utc\tctime_utc\tatime_utc\n"
        )
        row = (
            b"/dev/shm/.cache/upd\tfile\t0o666\t0\t0\t4096\t2026-01-02T03:15:00Z"
            b"\t2026-01-02T03:15:00Z\t2026-01-02T03:15:00Z\n"
        )
        files = {
            "triage/dev_shm_listing.txt": header + row,
            "dev/shm/.cache/upd": b"\x7fELF\x02\x01\x01" + b"\x00" * 20,
        }
        events = _parse(
            filesystem_suspicious, tmp_path, files, "evidence/triage/dev_shm_listing.txt",
        )
        assert len(events) == 1
        assert "elf" in events[0].tags
        assert events[0].event_type == "tmp_area_file"

    def test_tmp_listing_no_elf_tag_without_content(self, tmp_path):
        header = (
            b"path\ttype\tmode\tuid\tgid\tsize\tmtime_utc\tctime_utc\tatime_utc\n"
        )
        rows = b"/tmp/.x/x\tfile\t0o666\t0\t0\t4096\t2026-01-02T03:15:00Z\t2026-01-02T03:15:00Z\t2026-01-02T03:15:00Z\n"
        events = _parse(
            filesystem_suspicious, tmp_path,
            {"triage/tmp_listing.txt": header + rows},
            "evidence/triage/tmp_listing.txt",
        )
        assert len(events) == 1
        assert "elf" not in events[0].tags

    def test_header_only_is_skipped(self, tmp_path):
        blob = b"path\tmode\tuid\tgid\tsize\tmtime_utc\tflags\ttype\n"
        events = _parse(
            filesystem_suspicious, tmp_path,
            {"triage/suid_sgid.txt": blob}, "evidence/triage/suid_sgid.txt",
        )
        assert events == []

    def test_bad_row_marks_unparsed(self, tmp_path):
        blob = b"path\tmode\tuid\tgid\tsize\tmtime_utc\tflags\ttype\njust_one_column\n"
        events = _parse(
            filesystem_suspicious, tmp_path,
            {"triage/suid_sgid.txt": blob}, "evidence/triage/suid_sgid.txt",
        )
        assert events[0].event_type == "unparsed"

    def test_helper_rejects(self):
        assert filesystem_suspicious.parse_fs_message("nope") is None
        assert filesystem_suspicious.parse_iso("not-a-date") is None
        assert filesystem_suspicious.parse_iso(None) is None


# --------------------------------------------------------------- live_state


class TestLiveState:
    def test_ss_socket_parses_listen(self, tmp_path):
        blob = (
            b"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            b'tcp LISTEN 0 64 0.0.0.0:8080 0.0.0.0:* users:(("upd",pid=4152,fd=4))\n'
        )
        events = _parse(live_state, tmp_path, {"live/ss_tulpn.txt": blob},
                        "evidence/live/ss_tulpn.txt")
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "ss_socket"
        assert event.timestamp_utc == datetime(2026, 1, 3, 6, 0, 0, tzinfo=UTC)
        fields = live_state.parse_ss_message(event.message)
        assert fields["state"] == "LISTEN"
        assert fields["local"] == "0.0.0.0:8080"
        assert fields["process"] == "upd/4152"

    def test_lsof_entry(self, tmp_path):
        blob = (
            b"COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            b"x 4152 root 3u IPv4 54321 0t0 TCP 10.0.1.5:51234->203.0.113.9:4444 (ESTABLISHED)\n"
        )
        events = _parse(live_state, tmp_path, {"live/lsof_nP.txt": blob},
                        "evidence/live/lsof_nP.txt")
        assert events[0].event_type == "lsof_entry"
        fields = live_state.parse_lsof_message(events[0].message)
        assert fields["command"] == "x" and fields["pid"] == "4152"

    def test_who_and_last(self, tmp_path):
        who = b"root pts/1 2026-01-02 03:12 (203.0.113.9)\n"
        last = (
            b"root pts/1 203.0.113.9 Sat Jan 2 03:12 - 03:14 (00:02)\n"
            b"reboot system boot 6.1.0-18-amd64 Thu Jan 1 00:00 still running\n"
            b"wtmp begins Thu Jan 1 00:00:05 2026\n"
        )
        events = _parse(live_state, tmp_path, {"live/who.txt": who},
                        "evidence/live/who.txt")
        assert events[0].event_type == "who_session"
        assert "host=203.0.113.9" in events[0].message
        events = _parse(live_state, tmp_path, {"live/last.txt": last},
                        "evidence/live/last.txt")
        assert len(events) == 1
        assert events[0].event_type == "last_login"

    def test_lsmod_and_mount_and_docker(self, tmp_path):
        lsmod = b"Module Size Used by\ntls 131072 0\n"
        mount = b"tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
        docker = (
            b"CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES\n"
            b'a1b2c3d4e5f6 nginx "nginx -g daemon" 2 weeks ago Up 2 weeks 80/tcp web\n'
        )
        events = _parse(live_state, tmp_path, {"live/lsmod.txt": lsmod},
                        "evidence/live/lsmod.txt")
        assert events[0].event_type == "loaded_module"
        events = _parse(live_state, tmp_path, {"live/mount.txt": mount},
                        "evidence/live/mount.txt")
        assert events[0].event_type == "mount_entry"
        assert "target=/dev/shm" in events[0].message
        events = _parse(live_state, tmp_path, {"live/docker_ps_a.txt": docker},
                        "evidence/live/docker_ps_a.txt")
        assert events[0].event_type == "container_row"
        fields = live_state.parse_container_message(events[0].message)
        assert fields["image"] == "nginx" and fields["names"] == "web"

    def test_stderr_separator_skipped(self, tmp_path):
        blob = (
            b"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
            b"root 1 0.0 0.1 166484 11832 ? Ss Jan01 0:04 /sbin/init\n"
            b"<<<STDERR>>>\n"
            b"ps: error\n"
        )
        events = _parse(live_state, tmp_path, {"live/ps_auxf.txt": blob},
                        "evidence/live/ps_auxf.txt")
        assert len(events) == 2
        assert events[0].event_type == "process"
        assert events[1].event_type == "unparsed"

    def test_ps_depth_tag_from_indent(self, tmp_path):
        blob = (
            b"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
            b"root 1 0.0 0.1 166484 11832 ? Ss Jan01 0:04 /sbin/init\n"
            b"root 4150 0.0 0.1 18344 9200 ? Ss 03:12 0:00 sshd: root@pts/1\n"
            b"root 4152 0.0 0.0 11512 3400 pts/1 Ss 03:12 0:00 -bash\n"
            b"  root 4153 0.1 0.0 12112 2100 pts/1 S 03:15 0:11 /tmp/.x/x --daemon\n"
        )
        events = _parse(live_state, tmp_path, {"live/ps_auxf.txt": blob},
                        "evidence/live/ps_auxf.txt")
        depths = [e.tags[-1] for e in events]
        assert depths == ["depth:0", "depth:0", "depth:0", "depth:1"]
        info = live_state.parse_process_message(events[-1].message)
        assert info["command"] == "/tmp/.x/x --daemon"

    def test_helper_rejects(self):
        assert live_state.parse_ss_message("nope") is None
        assert live_state.parse_lsof_message("nope") is None
        assert live_state.parse_container_message("nope") is None
