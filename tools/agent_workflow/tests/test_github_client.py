"""MISSION-ROUTER-001 Amendment 026, vector 144 (router audit F14): every failure of the GitHub client is a
GitHubError, a read is tried again after a dropped connection, a timeout or a 5xx, and a write never is."""

from __future__ import annotations

import http.client
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mission_router import github  # noqa: E402
from mission_router.github import GitHub, GitHubError  # noqa: E402


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(status, message="x"):
    return urllib.error.HTTPError("https://api.github.com/x", status, "x", {},
                                  io.BytesIO(json.dumps({"message": message}).encode()))


class ClientTests(unittest.TestCase):
    def client(self, answers):
        """A client whose calls get ``answers`` in turn: an exception is raised, anything else is the body."""
        self.calls, self.sleeps = [], []
        queue = list(answers)

        def urlopen(req, timeout=30):
            self.calls.append((req.get_method(), req.full_url))
            answer = queue.pop(0)
            if isinstance(answer, BaseException):
                raise answer
            return Resp(json.dumps(answer).encode())

        patcher = mock.patch.object(github.urllib.request, "urlopen", urlopen)
        patcher.start()
        self.addCleanup(patcher.stop)
        return GitHub("t", "o/r", sleep=self.sleeps.append)

    def test_v144_a_dropped_connection_on_a_read_is_tried_again(self):
        gh = self.client([http.client.RemoteDisconnected("Remote end closed connection without response"), {"ok": 1}])
        self.assertEqual(gh.get("/issues"), {"ok": 1})
        self.assertEqual((len(self.calls), self.sleeps), (2, [1.0]))

    def test_v144_a_read_that_keeps_failing_is_a_github_error(self):
        for name, answer, status in (("5xx", http_error(502, "Bad Gateway"), 502),
                                     ("url", urllib.error.URLError("temporary failure in name resolution"), 0),
                                     ("timeout", TimeoutError("timed out"), 0),
                                     ("reset", ConnectionResetError(104, "Connection reset by peer"), 0)):
            with self.subTest(name):
                gh = self.client([answer] * 3)
                with self.assertRaises(GitHubError) as caught:
                    gh.get("/commits/abc/check-runs")
                self.assertEqual(caught.exception.status, status)
                self.assertEqual((len(self.calls), self.sleeps), (3, [1.0, 3.0]))

    def test_v144_a_write_is_never_sent_twice(self):
        for name, answer, status in (("dropped", http.client.RemoteDisconnected("closed"), 0),
                                     ("5xx", http_error(502), 502)):
            with self.subTest(name):
                gh = self.client([answer])
                with self.assertRaises(GitHubError) as caught:
                    gh.request("PUT", "/pulls/7/merge", {"sha": "a" * 40})
                self.assertEqual((caught.exception.status, len(self.calls), self.sleeps), (status, 1, []))

    def test_v144_a_rate_limit_or_a_refusal_is_not_tried_again(self):
        for status in (403, 404, 422, 429):
            with self.subTest(status):
                gh = self.client([http_error(status, "API rate limit exceeded")])
                with self.assertRaises(GitHubError) as caught:
                    gh.get("/labels")
                self.assertEqual((caught.exception.status, len(self.calls)), (status, 1))
                self.assertIn("rate limit", caught.exception.message)

    def test_a_plain_answer_is_one_call(self):
        gh = self.client([[{"name": "x"}]])
        self.assertEqual(gh.get("/labels"), [{"name": "x"}])
        self.assertEqual((len(self.calls), self.sleeps), (1, []))


if __name__ == "__main__":
    unittest.main()
