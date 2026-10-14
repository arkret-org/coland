"""Real SFU probe; credentials arrive through stdin and are never logged."""
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile

import aiohttp
from livekit import api, rtc


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as lease:
        lease.bind(("127.0.0.1", 0))
        return lease.getsockname()[1]


async def run(data):
    config = {
        "port": data["port"],
        "bind_addresses": ["127.0.0.1"],
        "keys": {data["api_key"]: data["api_secret"]},
        "rtc": {"tcp_port": port(), "udp_port": port(socket.SOCK_DGRAM),
                "node_ip": "127.0.0.1", "use_external_ip": False},
        "logging": {"level": "error"},
    }
    # JSON is YAML-compatible; the file belongs to this owned test process.
    with tempfile.TemporaryDirectory(prefix="2136-sfu-") as root:
        path = os.path.join(root, "livekit.yaml")
        with open(path, "w", encoding="utf-8") as file:
            json.dump(config, file)
        server = subprocess.Popen(
            [os.environ["COLAND_TEST_LIVEKIT_BIN"], "--config", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        rooms = [rtc.Room(), rtc.Room()]
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("owned SFU exited during startup")
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", data["port"])
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            else:
                raise RuntimeError("owned SFU startup timed out")
            subscribed = asyncio.Event()
            @rooms[0].on("track_subscribed")
            def received(track, publication, participant):
                subscribed.set()
            for room, token in zip(rooms, data["tokens"]):
                await room.connect(f'ws://127.0.0.1:{data["port"]}', token)
            sources = [rtc.AudioSource(48000, 1), rtc.AudioSource(48000, 1)]
            tracks = [rtc.LocalAudioTrack.create_audio_track("audio", source) for source in sources]
            publications = []
            for room, track in zip(rooms, tracks):
                publications.append(await room.local_participant.publish_track(
                    track, rtc.TrackPublishOptions(source=rtc.TrackSource.SOURCE_MICROPHONE)))
            for _ in range(10):
                for source in sources:
                    await source.capture_frame(rtc.AudioFrame(bytes(960), 48000, 1, 480))
            await asyncio.wait_for(subscribed.wait(), timeout=15)
            assert not publications[1].muted
            request = api.MuteRoomTrackRequest(
                room=rooms[0].name, identity=rooms[1].local_participant.identity,
                track_sid=publications[1].sid, muted=True,
            )
            async with aiohttp.ClientSession() as http:
                async with http.post(
                    f'http://127.0.0.1:{data["port"]}/twirp/livekit.RoomService/MutePublishedTrack',
                    data=request.SerializeToString(),
                    headers={"Content-Type": "application/protobuf",
                             "Authorization": "Bearer " + data["tokens"][0]},
                ) as response:
                    assert response.status in (401, 403), "media token acquired moderator authority"
            assert not publications[1].muted, "refused moderation muted another publisher"
            tracks[0].mute()
            await asyncio.sleep(0.1)
            assert tracks[0].muted, "self mute did not reach the own publication"
            assert not tracks[1].muted, "self mute changed another publication"
            tracks[0].unmute()
            assert not tracks[0].muted
            print("[native-sfu] production_issuer_tokens=1 two_actual_webrtc_publishers=1 "
                  "actual_subscription=1 cross_publisher_mute_refused=1 self_mute_unmute=1")
        finally:
            for room in rooms:
                await room.disconnect()
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(run(json.load(sys.stdin)), timeout=60))
