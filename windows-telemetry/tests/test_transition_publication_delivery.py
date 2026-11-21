import io
import json
import logging
import os
from urllib.error import HTTPError
from unittest.mock import Mock, patch

import pytest

from collectors.mailbox import TransitionMailbox
from transport.client import SendResult, TransitionTransportClient
from transport.delivery import DeliveryManager


def test_mailbox_retry_does_not_reopen_stale_hardlink(tmp_path):
    mailbox = TransitionMailbox(str(tmp_path), logging.getLogger(__name__))
    pending = tmp_path / "pending"
    pending.mkdir()
    original = {"transition_id": "tid", "created_at": "original", "witness_payload": {"record_id": 1}}
    target = pending / "tid.json"
    target.write_text(json.dumps(original), encoding="utf-8")
    stale = pending / "tid.json.tmp"
    os.link(target, stale)

    mailbox.publish_transition(dict(original, created_at="retry"))
    conflicting = dict(original, witness_payload={"record_id": 2})
    with pytest.raises(ValueError, match="Conflicting transition envelope"):
        mailbox.publish_transition(conflicting)

    assert json.loads(target.read_text(encoding="utf-8")) == original
    assert json.loads(stale.read_text(encoding="utf-8")) == original
    assert json.loads((tmp_path / "quarantined" / "tid.json").read_text(encoding="utf-8")) == conflicting
    assert list(pending.glob("*.tmp")) == [stale]


def test_mailbox_quarantines_malformed_target_and_recovers(tmp_path):
    mailbox = TransitionMailbox(str(tmp_path), logging.getLogger(__name__))
    pending = tmp_path / "pending"
    pending.mkdir()
    target = pending / "tid.json"
    target.write_bytes(b'{"transition_id":')
    envelope = {"transition_id": "tid", "identity_manifest": {}, "witness_payload": {}}

    assert mailbox.publish_transition(envelope) == "tid"
    assert json.loads(target.read_text(encoding="utf-8")) == envelope
    assert (tmp_path / "quarantined" / "tid.json").read_bytes() == b'{"transition_id":'
    assert not list(pending.glob("*.tmp"))


@pytest.mark.parametrize(
    ("status", "body", "method"),
    [
        (200, {"status": "APPLIED", "transition_id": "wrong"}, "mark_failed"),
        (200, {"status": "APPLIED"}, "mark_failed"),
        (200, {"status": "APPLIED", "transition_id": "tid"}, "mark_delivered"),
        (409, {"duplicate": True, "transition_id": "tid"}, "mark_quarantined"),
        (409, {"duplicate": True, "accepted": True, "transition_id": "wrong"}, "mark_quarantined"),
        (409, {"duplicate": True, "accepted": True, "transition_id": "tid"}, "mark_delivered"),
    ],
)
def test_outbox_requires_acknowledgement_of_submitted_transition(status, body, method):
    outbox = Mock()
    outbox.get_pending_transitions.return_value = [
        {"transition_id": "tid", "transition_data": '{"transition_id": "tid"}'}
    ]
    logger = logging.getLogger(__name__)
    client = TransitionTransportClient("http://localhost/transition", "test-agent-token", logger)
    manager = DeliveryManager(
        Mock(), Mock(), logger, transition_outbox=outbox,
        transition_client=client, allow_unlocked_for_testing=True,
    )

    data = json.dumps(body).encode()
    with patch("transport.client.urllib.request.urlopen") as urlopen:
        if status == 409:
            urlopen.side_effect = HTTPError(client.endpoint_url, status, "Conflict", {}, io.BytesIO(data))
        else:
            urlopen.return_value.__enter__.return_value = Mock(
                status=status, headers={}, **{"read.return_value": data}
            )
        manager.process_transition_outbox()

    for state_change in ("mark_failed", "mark_quarantined", "mark_delivered"):
        assert getattr(outbox, state_change).call_count == int(method == state_change)


def test_outbox_does_not_deliver_when_client_rejects_acknowledgement():
    outbox = Mock()
    outbox.get_pending_transitions.return_value = [
        {"transition_id": "tid", "transition_data": '{"transition_id": "tid"}'}
    ]
    client = Mock()
    client.send_transition.return_value = SendResult(
        False, False, "Client rejected acknowledgement", status_code=200,
        response_body='{"status": "APPLIED", "transition_id": "tid"}',
    )
    manager = DeliveryManager(
        Mock(), Mock(), logging.getLogger(__name__), transition_outbox=outbox,
        transition_client=client, allow_unlocked_for_testing=True,
    )

    manager.process_transition_outbox()

    outbox.mark_failed.assert_called_once()
    outbox.mark_delivered.assert_not_called()
