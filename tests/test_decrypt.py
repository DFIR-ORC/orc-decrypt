import hashlib
import logging
import os
from inspect import getfullargspec

import pytest

from src.orcdecrypt.decrypt import decrypt_archive

test_results_valid_recipient = [
    ("archive_aes.7z.p7b", True, "edcb3c7bf0901ba2d8581179bc8a69dc26bce571"),
    ("archive_des.7z.p7b", True, "8ad404def35c4ed554e350cb36e331a779901052"),
    ("archive_aes_corrupted.7z.p7b", False, None),
    ("archive_des_corrupted.7z.p7b", False, None),
    ("archive_aes_truncated.7z.p7b", False, None),
    ("archive_des_truncated.7z.p7b", False, None),
    ("archive_aes_padded.7z.p7b", True, "edcb3c7bf0901ba2d8581179bc8a69dc26bce571"),
    ("archive_des_padded.7z.p7b", True, "8ad404def35c4ed554e350cb36e331a779901052"),
]
test_results_invalid_recipient = [
    ("archive_aes.7z.p7b", False, None),
    ("archive_des.7z.p7b", False, None),
    ("archive_aes_corrupted.7z.p7b", False, None),
    ("archive_des_corrupted.7z.p7b", False, None),
    ("archive_aes_truncated.7z.p7b", False, None),
    ("archive_des_truncated.7z.p7b", False, None),
    ("archive_aes_padded.7z.p7b", False, None),
    ("archive_des_padded.7z.p7b", False, None),
]


@pytest.mark.parametrize(
    "input_file, expected_return, expected_hash",
    test_results_valid_recipient,
    indirect=["input_file"],
)
def test_decrypt_python_with_valid_recipient(
    input_file,
    expected_return,
    expected_hash,
    valid_recipient_key,
    unstream_cmd,
    tmp_path,
):
    msg = (
        "Failed to decrypt archive with Python implementation."
        if expected_return
        else "Decryption process returned True whereas it should have failed"
    )
    output_path = tmp_path / "archive.7z"

    assert (
        decrypt_archive(
            input_file, valid_recipient_key, output_path, unstream_cmd, method="python"
        )
        == expected_return
    ), msg
    if expected_return:
        with open(output_path, "rb") as f_archive:
            if "usedforsecurity" in getfullargspec(hashlib.sha1).kwonlyargs:
                sha1sum = hashlib.sha1(
                    f_archive.read(), usedforsecurity=False
                ).hexdigest()
            else:
                sha1sum = hashlib.sha1(f_archive.read()).hexdigest()
            assert (
                sha1sum == expected_hash
            ), f"Decrypted archive has the wrong SHA1: {sha1sum}"
    output_path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_return, expected_hash",
    test_results_valid_recipient,
    indirect=["input_file"],
)
def test_decrypt_python_with_valid_recipient_encrypted(
    input_file,
    expected_return,
    expected_hash,
    valid_recipient_key_encrypted,
    key_password,
    unstream_cmd,
    tmp_path,
):
    msg = (
        "Failed to decrypt archive with Python implementation."
        if expected_return
        else "Decryption process returned True whereas it should have failed"
    )
    output_path = tmp_path / "archive.7z"

    assert (
        decrypt_archive(
            input_file,
            valid_recipient_key_encrypted,
            output_path,
            unstream_cmd,
            method="python",
            password=key_password,
        )
        == expected_return
    ), msg
    if expected_return:
        with open(output_path, "rb") as f_archive:
            if "usedforsecurity" in getfullargspec(hashlib.sha1).kwonlyargs:
                sha1sum = hashlib.sha1(
                    f_archive.read(), usedforsecurity=False
                ).hexdigest()
            else:
                sha1sum = hashlib.sha1(f_archive.read()).hexdigest()
            assert (
                sha1sum == expected_hash
            ), f"Decrypted archive has the wrong SHA1: {sha1sum}"
    output_path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_return, expected_hash",
    test_results_invalid_recipient,
    indirect=["input_file"],
)
def test_decrypt_python_with_invalid_recipient(
    input_file,
    expected_return,
    expected_hash,
    invalid_recipient_key,
    unstream_cmd,
    tmp_path,
):
    output_path = tmp_path / "archive.7z"
    assert not decrypt_archive(
        input_file,
        invalid_recipient_key,
        output_path,
        unstream_cmd,
        method="python",
    ), "Decryption process returned True whereas the key provided was invalid for this archive."
    output_path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_return, expected_hash",
    test_results_valid_recipient,
    indirect=["input_file"],
)
def test_decrypt_openssl_with_valid_recipient(
    input_file,
    expected_return,
    expected_hash,
    valid_recipient_key,
    unstream_cmd,
    tmp_path,
):
    msg = (
        "Failed to decrypt archive with OpenSSL implementation."
        if expected_return
        else "Decryption process returned True whereas it should have failed"
    )
    output_path = tmp_path / "archive.7z"
    assert (
        decrypt_archive(
            input_file, valid_recipient_key, output_path, unstream_cmd, method="openssl"
        )
        == expected_return
    ), msg
    if expected_return:
        with open(output_path, "rb") as f_archive:
            if "usedforsecurity" in getfullargspec(hashlib.sha1).kwonlyargs:
                sha1sum = hashlib.sha1(
                    f_archive.read(), usedforsecurity=False
                ).hexdigest()
            else:
                sha1sum = hashlib.sha1(f_archive.read()).hexdigest()
            assert (
                sha1sum == expected_hash
            ), f"Decrypted archive has the wrong SHA1: {sha1sum}"
    output_path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_return, expected_hash",
    test_results_valid_recipient,
    indirect=["input_file"],
)
def test_decrypt_openssl_with_valid_recipient_encrypted(
    input_file,
    expected_return,
    expected_hash,
    valid_recipient_key_encrypted,
    key_password,
    unstream_cmd,
    tmp_path,
):
    msg = (
        "Failed to decrypt archive with OpenSSL implementation."
        if expected_return
        else "Decryption process returned True whereas it should have failed"
    )
    output_path = tmp_path / "archive.7z"
    assert (
        decrypt_archive(
            input_file,
            valid_recipient_key_encrypted,
            output_path,
            unstream_cmd,
            method="openssl",
            password=key_password,
        )
        == expected_return
    ), msg
    if expected_return:
        with open(output_path, "rb") as f_archive:
            if "usedforsecurity" in getfullargspec(hashlib.sha1).kwonlyargs:
                sha1sum = hashlib.sha1(
                    f_archive.read(), usedforsecurity=False
                ).hexdigest()
            else:
                sha1sum = hashlib.sha1(f_archive.read()).hexdigest()
            assert (
                sha1sum == expected_hash
            ), f"Decrypted archive has the wrong SHA1: {sha1sum}"
    output_path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_return, expected_hash",
    test_results_invalid_recipient,
    indirect=["input_file"],
)
def test_decrypt_openssl_with_invalid_recipient(
    input_file,
    expected_return,
    expected_hash,
    invalid_recipient_key,
    unstream_cmd,
    tmp_path,
):
    output_path = tmp_path / "archive.7z"
    assert not decrypt_archive(
        input_file, invalid_recipient_key, output_path, unstream_cmd, method="openssl"
    ), "Decryption process returned True whereas the key provided was invalid for this archive."
    output_path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_return, expected_hash",
    test_results_valid_recipient,
    indirect=["input_file"],
)
def test_decrypt_auto_with_valid_recipient(
    input_file,
    expected_return,
    expected_hash,
    valid_recipient_key,
    unstream_cmd,
    tmp_path,
    caplog,
):
    msg = (
        "Failed to decrypt archive with automatic method detection."
        if expected_return
        else "Decryption process returned True whereas it should have failed"
    )
    caplog.set_level(logging.DEBUG)
    output_path = tmp_path / "archive.7z"
    assert (
        decrypt_archive(input_file, valid_recipient_key, output_path, unstream_cmd)
        == expected_return
    ), msg
    assert any(" using OpenSSL" in record[2] for record in caplog.record_tuples)
    if expected_return:
        with open(output_path, "rb") as f_archive:
            if "usedforsecurity" in getfullargspec(hashlib.sha1).kwonlyargs:
                sha1sum = hashlib.sha1(
                    f_archive.read(), usedforsecurity=False
                ).hexdigest()
            else:
                sha1sum = hashlib.sha1(f_archive.read()).hexdigest()
            assert (
                sha1sum == expected_hash
            ), f"Decrypted archive has the wrong SHA1: {sha1sum}"
    output_path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "input_file, expected_return, expected_hash",
    test_results_invalid_recipient,
    indirect=["input_file"],
)
def test_decrypt_auto_with_invalid_recipient(
    input_file,
    expected_return,
    expected_hash,
    invalid_recipient_key,
    unstream_cmd,
    tmp_path,
    caplog,
):
    output_path = tmp_path / "archive.7z"
    caplog.set_level(logging.DEBUG)
    assert not decrypt_archive(
        input_file, invalid_recipient_key, output_path, unstream_cmd
    ), "Decryption process returned True whereas the key provided was invalid for this archive."
    assert any(" using OpenSSL" in record[2] for record in caplog.record_tuples)
    output_path.unlink(missing_ok=True)


def test_decrypt_auto_without_openssl(
    valid_archive,
    valid_recipient_key,
    unstream_cmd,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
):
    output_path = tmp_path / "archive.7z"
    caplog.set_level(logging.DEBUG)
    old_path = os.environ["PATH"]
    os.environ.update(PATH="")
    assert decrypt_archive(
        valid_archive, valid_recipient_key, output_path, unstream_cmd
    ), "Decryption process failed whereas it should have fell back to python decryption."
    os.environ.update(PATH=old_path)
    assert any(
        " using Python implementation" in record.message for record in caplog.records
    )
    assert any(
        "OpenSSL binary could not be found in the PATH, falling back to python"
        in record.message
        for record in caplog.records
    )
    output_path.unlink(missing_ok=True)


def test_decrypt_openssl_without_openssl(
    valid_archive,
    valid_recipient_key,
    unstream_cmd,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
):
    output_path = tmp_path / "archive.7z"
    caplog.set_level(logging.DEBUG)
    old_path = os.environ["PATH"]
    os.environ.update(PATH="")
    with pytest.raises(
        FileNotFoundError, match="OpenSSL binary could not be found in the PATH"
    ):
        decrypt_archive(
            valid_archive,
            valid_recipient_key,
            output_path,
            unstream_cmd,
            method="openssl",
        )
    os.environ.update(PATH=old_path)
    output_path.unlink(missing_ok=True)


def test_decrypt_twice_without_force(
    valid_archive, valid_recipient_key, unstream_cmd, tmp_path, caplog, method
):
    output_path = tmp_path / "archive.7z"
    caplog.set_level(logging.DEBUG)
    assert decrypt_archive(
        valid_archive, valid_recipient_key, output_path, unstream_cmd, method=method
    ), "Failed to decrypt archive with OpenSSL."
    assert not decrypt_archive(
        valid_archive, valid_recipient_key, output_path, unstream_cmd, method=method
    ), "Decryption process should have failed because of existing output file."
    assert any(
        " already exists, skipping (use --force to overwrite)" in record[2]
        for record in caplog.record_tuples
    )
    output_path.unlink(missing_ok=True)


def test_decrypt_twice_with_force(
    valid_archive,
    valid_recipient_key,
    unstream_cmd,
    tmp_path,
    caplog,
    method,
):
    output_path = tmp_path / "archive.7z"
    caplog.set_level(logging.DEBUG)
    assert decrypt_archive(
        valid_archive, valid_recipient_key, output_path, unstream_cmd, method=method
    ), "Failed to decrypt archive with OpenSSL."
    assert decrypt_archive(
        valid_archive,
        valid_recipient_key,
        output_path,
        unstream_cmd,
        method=method,
        force=True,
    ), "Failed to decrypt archive with OpenSSL."
    output_path.unlink(missing_ok=True)
