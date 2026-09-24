import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from src.detect import detect, read_events

ROOT = Path(__file__).resolve().parents[1]


def event(minute, user, ip='198.51.100.10', result='failure'):
    return dict(time=datetime(2026, 9, 1, 12, minute, tzinfo=timezone.utc),
                user=user, ip_address=ip, result=result)


class DetectorTests(unittest.TestCase):
    def test_spray_fixture(self):
        alert, = detect(read_events(ROOT / 'data/spray.csv'))
        self.assertEqual(alert['source_ip'], '198.51.100.10')
        self.assertEqual(alert['distinct_users'], 3)
        self.assertEqual(alert['failed_attempts'], 3)

    def test_benign_fixture(self):
        self.assertEqual(detect(read_events(ROOT / 'data/benign.csv')), [])

    def test_unsorted_input(self):
        self.assertEqual(len(detect([event(5, 'c'), event(0, 'a'), event(2, 'b')])), 1)

    def test_exact_window_boundary(self):
        self.assertEqual(len(detect([event(0, 'a'), event(5, 'b'), event(10, 'c')])), 1)

    def test_outside_window(self):
        self.assertEqual(detect([event(0, 'a'), event(5, 'b'), event(11, 'c')]), [])

    def test_ips_not_combined(self):
        self.assertEqual(detect([event(0, 'a'), event(1, 'b'), event(2, 'c', '203.0.113.20')]), [])

    def test_success_not_counted(self):
        self.assertEqual(detect([event(0, 'a'), event(1, 'b'), event(2, 'c', result='success')]), [])

    def test_threshold_tuning(self):
        self.assertEqual(detect(read_events(ROOT / 'data/spray.csv'), min_users=4), [])

    def test_empty_input(self):
        self.assertEqual(detect([]), [])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect([], min_users=1)

    def test_bad_csv_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bad.csv'
            path.write_text('user\na\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'headers'):
                read_events(path)

    def test_bad_result_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bad.csv'
            path.write_text('timestamp,user,ip_address,result\n2026-09-01T12:00:00Z,a,198.51.100.10,unknown\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'line 2'):
                read_events(path)


if __name__ == '__main__':
    unittest.main()
