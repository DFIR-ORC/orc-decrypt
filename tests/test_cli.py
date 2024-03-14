import hashlib
import os
from inspect import getfullargspec

import pytest

from src.orcdecrypt.cli import entrypoint

test_results_valid_recipient = [
    ("archive_aes.7z.p7b", 1, "edcb3c7bf0901ba2d8581179bc8a69dc26bce571"),
    ("archive_des.7z.p7b", 1, "8ad404def35c4ed554e350cb36e331a779901052"),
    ("archive_aes_corrupted.7z.p7b", 0, None),
    ("archive_des_corrupted.7z.p7b", 0, None),
    ("archive_aes_truncated.7z.p7b", 0, None),
    ("archive_des_truncated.7z.p7b", 0, None),
    ("archive_aes_padded.7z.p7b", 1, "edcb3c7bf0901ba2d8581179bc8a69dc26bce571"),
    ("archive_des_padded.7z.p7b", 1, "8ad404def35c4ed554e350cb36e331a779901052"),
]
test_results_invalid_recipient = [
    ("archive_aes.7z.p7b", 0, None),
    ("archive_des.7z.p7b", 0, None),
    ("archive_aes_corrupted.7z.p7b", 0, None),
    ("archive_des_corrupted.7z.p7b", 0, None),
    ("archive_aes_truncated.7z.p7b", 0, None),
    ("archive_des_truncated.7z.p7b", 0, None),
    ("archive_aes_padded.7z.p7b", 0, None),
    ("archive_des_padded.7z.p7b", 0, None),
]


@pytest.mark.parametrize(
    "input_file, expected_decrypted_archives, expected_hash",
    test_results_valid_recipient,
    indirect=["input_file"],
)
def test_cli_python_with_valid_recipient(
    input_file,
    expected_decrypted_archives,
    expected_hash,
    valid_recipient_keys,
    unstream_cmd,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
):
    msg = (
        "Decryption process succeeded whereas it should have failed."
        if expected_decrypted_archives == 0
        else "Failed to decrypt archive with Python implementation."
    )
    for key in valid_recipient_keys:
        ret = entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(key),
                "--unstream-path",
                str(unstream_cmd),
                "--output",
                str(tmp_path),
                "--method",
                "python",
                str(input_file),
            ]
        )
        assert ret == 0, "Unexpected script error"
        assert (
            f"{int(not expected_decrypted_archives)} failed, {expected_decrypted_archives} succeeded"
            in caplog.records[-1].message
        ), msg
        if expected_decrypted_archives > 0:
            with open(tmp_path / input_file.stem, "rb") as f_archive:
                if "usedforsecurity" in getfullargspec(hashlib.sha1).kwonlyargs:
                    sha1sum = hashlib.sha1(
                        f_archive.read(), usedforsecurity=False
                    ).hexdigest()
                else:
                    sha1sum = hashlib.sha1(f_archive.read()).hexdigest()
                assert (
                    sha1sum == expected_hash
                ), f"Decrypted archive has the wrong SHA1: {sha1sum}"
        (tmp_path / input_file.stem).unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_decrypted_archives, expected_hash",
    test_results_invalid_recipient,
    indirect=["input_file"],
)
def test_cli_python_with_invalid_recipient(
    input_file,
    expected_decrypted_archives,
    expected_hash,
    invalid_recipient_keys,
    unstream_cmd,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
):
    for key in invalid_recipient_keys:
        ret = entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(key),
                "--unstream-path",
                str(unstream_cmd),
                "--output",
                str(tmp_path),
                "--method",
                "python",
                str(input_file),
            ]
        )
        assert ret == 0, "Unexpected script error"
        assert (
            f"{int( not expected_decrypted_archives)} failed, {expected_decrypted_archives} succeeded"
            in caplog.records[-1].message
        ), "Decryption process succeeded whereas the key provided was invalid for this archive."
        (tmp_path / input_file.stem).unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_decrypted_archives, expected_hash",
    test_results_valid_recipient,
    indirect=["input_file"],
)
def test_cli_openssl_with_valid_recipient(
    input_file,
    expected_decrypted_archives,
    expected_hash,
    valid_recipient_keys,
    unstream_cmd,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
):
    msg = (
        "Decryption process succeeded whereas it should have failed."
        if expected_decrypted_archives == 0
        else "Failed to decrypt archive with OpenSSL."
    )
    for key in valid_recipient_keys:
        ret = entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(key),
                "--unstream-path",
                str(unstream_cmd),
                "--output",
                str(tmp_path),
                "--method",
                "openssl",
                str(input_file),
            ]
        )
        assert ret == 0, "Unexpected script error"
        assert (
            f"{int(not expected_decrypted_archives)} failed, {expected_decrypted_archives} succeeded"
            in caplog.records[-1].message
        ), msg
        if expected_decrypted_archives > 0:
            with open(tmp_path / input_file.stem, "rb") as f_archive:
                if "usedforsecurity" in getfullargspec(hashlib.sha1).kwonlyargs:
                    sha1sum = hashlib.sha1(
                        f_archive.read(), usedforsecurity=False
                    ).hexdigest()
                else:
                    sha1sum = hashlib.sha1(f_archive.read()).hexdigest()
                assert (
                    sha1sum == expected_hash
                ), f"Decrypted archive has the wrong SHA1: {sha1sum}"
        (tmp_path / input_file.stem).unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_decrypted_archives, expected_hash",
    test_results_invalid_recipient,
    indirect=["input_file"],
)
def test_cli_openssl_with_invalid_recipient(
    input_file,
    expected_decrypted_archives,
    expected_hash,
    invalid_recipient_keys,
    unstream_cmd,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
):
    for key in invalid_recipient_keys:
        ret = entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(key),
                "--unstream-path",
                str(unstream_cmd),
                "--output",
                str(tmp_path),
                "--method",
                "openssl",
                str(input_file),
            ]
        )
        assert ret == 0, "Unexpected script error"
        assert (
            f"{int(not expected_decrypted_archives)} failed, {expected_decrypted_archives} succeeded"
            in caplog.records[-1].message
        ), "Decryption process succeeded whereas the key provided was invalid for this archive."
        (tmp_path / input_file.stem).unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_decrypted_archives, expected_hash",
    test_results_valid_recipient,
    indirect=["input_file"],
)
def test_cli_auto_with_valid_recipient(
    input_file,
    expected_decrypted_archives,
    expected_hash,
    valid_recipient_keys,
    unstream_cmd,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
):
    msg = (
        "Decryption process succeeded whereas it should have failed."
        if expected_decrypted_archives == 0
        else "Failed to decrypt archive with OpenSSL implementation."
    )
    for key in valid_recipient_keys:
        ret = entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(key),
                "--log-level",
                "DEBUG",
                "--unstream-path",
                str(unstream_cmd),
                "--output",
                str(tmp_path),
                str(input_file),
            ]
        )
        assert ret == 0, "Unexpected script error"
        assert (
            f"{int(not expected_decrypted_archives)} failed, {expected_decrypted_archives} succeeded"
            in caplog.records[-1].message
        ), msg
        if expected_decrypted_archives > 0:
            with open(tmp_path / input_file.stem, "rb") as f_archive:
                if "usedforsecurity" in getfullargspec(hashlib.sha1).kwonlyargs:
                    sha1sum = hashlib.sha1(
                        f_archive.read(), usedforsecurity=False
                    ).hexdigest()
                else:
                    sha1sum = hashlib.sha1(f_archive.read()).hexdigest()
                assert (
                    sha1sum == expected_hash
                ), f"Decrypted archive has the wrong SHA1: {sha1sum}"
        (tmp_path / input_file.stem).unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_decrypted_archives, expected_hash",
    test_results_invalid_recipient,
    indirect=["input_file"],
)
def test_cli_auto_with_invalid_recipient(
    input_file,
    expected_decrypted_archives,
    expected_hash,
    invalid_recipient_keys,
    unstream_cmd,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
):
    for key in invalid_recipient_keys:
        ret = entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(key),
                "--log-level",
                "DEBUG",
                "--unstream-path",
                str(unstream_cmd),
                "--output",
                str(tmp_path),
                str(input_file),
            ]
        )
        assert ret == 0, "Unexpected script error"
        assert (
            f"{int(not expected_decrypted_archives)} failed, {expected_decrypted_archives} succeeded"
            in caplog.records[-1].message
        ), "Decryption process succeeded whereas the key provided was invalid for this archive."
        (tmp_path / input_file.stem).unlink(missing_ok=True)


def test_cli_with_empty_input(
    valid_recipient_keys, unstream_cmd, tmp_path, caplog: pytest.LogCaptureFixture
):
    ret = entrypoint(
        [
            "-j",
            "1",
            "-k",
            str(valid_recipient_keys[0]),
            "--log-level",
            "DEBUG",
            "--log-file",
            str(tmp_path / "orcdecrypt.log"),
            "--unstream-path",
            str(unstream_cmd),
            "--output",
            str(tmp_path),
            str(tmp_path),
        ]
    )
    assert ret == 0, "Unexpected script error"
    assert (
        "No encrypted archives could be found in input path(s), nothing to do."
        in caplog.records[-1].message
    )


def test_cli_without_unstream(
    valid_recipient_keys, tmp_path, caplog: pytest.LogCaptureFixture
):
    old_path = os.environ["PATH"]
    os.environ.update(PATH="")
    ret = entrypoint(
        [
            "-j",
            "1",
            "-k",
            str(valid_recipient_keys[0]),
            "--log-level",
            "DEBUG",
            "--log-file",
            str(tmp_path / "orcdecrypt.log"),
            "--output",
            str(tmp_path),
            "test_data",
        ]
    )
    os.environ.update(PATH=old_path)
    assert (
        ret == -1
    ), "Return code should have been -1 since unstream can not be found in this environment."
    assert (
        'Missing tool "unstream" in PATH, please provide the path to unstream binary with --unstream-path'
        in caplog.records[-1].message
    )


def test_cli_with_invalid_unstream(
    valid_recipient_keys, tmp_path, capsys: pytest.CaptureFixture
):
    with pytest.raises(SystemExit) as e:
        entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(valid_recipient_keys[0]),
                "--log-level",
                "DEBUG",
                "--log-file",
                str(tmp_path / "orcdecrypt.log"),
                "--output",
                str(tmp_path),
                "--unstream-path",
                "/non/existent" "test_data",
            ]
        )
    assert (
        e.value.code == 2
    ), "Return code should have been 2 (incorrect usage) since unstream path does not exist."
    assert "is not a valid file" in capsys.readouterr().err


def test_cli_with_invalid_key(tmp_path, capsys: pytest.CaptureFixture):
    invalid_key = tmp_path / "invalid_key.pem"
    invalid_key.touch()
    with pytest.raises(SystemExit) as e:
        entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(invalid_key),
                "--log-level",
                "DEBUG",
                "--log-file",
                str(tmp_path / "orcdecrypt.log"),
                "--output",
                str(tmp_path),
                "test_data",
            ]
        )
    assert (
        e.value.code == 2
    ), f"Return code should have been 2 (incorrect usage) since {invalid_key} is an invalid private key."
    assert "is not a valid private key" in capsys.readouterr().err


def test_cli_with_inexistant_input(
    valid_recipient_keys,
    tmp_path,
    capsys: pytest.CaptureFixture,
):
    with pytest.raises(SystemExit) as e:
        entrypoint(
            [
                "-j",
                "1",
                "-k",
                str(valid_recipient_keys[0]),
                "--log-level",
                "DEBUG",
                "--log-file",
                str(tmp_path / "orcdecrypt.log"),
                "--output",
                str(tmp_path),
                "no_data",
            ]
        )
    assert (
        e.value.code == 2
    ), "Return code should have been 2 (incorrect usage) since the input does not exist."
    assert "does not exist" in capsys.readouterr().err


def test_cli_with_input_directories(
    valid_recipient_keys,
    unstream_cmd,
    tmp_path,
    test_data_dir,
    caplog: pytest.LogCaptureFixture,
):
    ret = entrypoint(
        [
            "-j",
            "1",
            "-k",
            str(valid_recipient_keys[0]),
            "--unstream-path",
            str(unstream_cmd),
            "--log-level",
            "DEBUG",
            "--log-file",
            str(tmp_path / "orcdecrypt.log"),
            "--output",
            str(tmp_path),
            str(test_data_dir / "subdir_a"),
            str(test_data_dir / "subdir_b"),
        ]
    )
    assert ret == 0, "Unexpected script error"
    assert (
        "0 failed, 4 succeeded" in caplog.records[-1].message
    ), "Failed to decrypt archive with OpenSSL implementation."
    assert (tmp_path / "subdir_1" / "archive_aes.7z").exists()
    assert (tmp_path / "subdir_2" / "archive_aes.7z").exists()
    assert (tmp_path / "archive_aes.7z").exists()
    assert (tmp_path / "archive_des.7z").exists()
