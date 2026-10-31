"""Small stdlib-only wrapper around macOS generic-password Keychain items."""
from __future__ import annotations

import ctypes
import re
import sys


class KeychainError(Exception):
    """A generic, non-secret Keychain operation failure."""


class MacKeychain:
    SERVICE = "io.github.gmperkinsmba.teleport"
    ACCOUNT_PATTERN = re.compile(r"(?:token|pairing_key)-[a-f0-9]{64}-[a-f0-9]{32}")
    ERR_ITEM_NOT_FOUND = -25300

    def __init__(self, service: str | None = None) -> None:
        if sys.platform != "darwin":
            raise KeychainError("macOS Keychain is unavailable")
        if service is not None and not re.fullmatch(r"io\.github\.gmperkinsmba\.teleport\.probe\.[a-f0-9]{32}", service):
            raise KeychainError("macOS Keychain operation failed")
        self.service = service or self.SERVICE
        try:
            self._security = ctypes.CDLL(
                "/System/Library/Frameworks/Security.framework/Security")
            self._cf = ctypes.CDLL(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
            self._configure_functions()
        except Exception:
            raise KeychainError("macOS Keychain is unavailable") from None

    def _configure_functions(self) -> None:
        self._cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        self._cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        self._cf.CFDataCreate.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_long]
        self._cf.CFDataCreate.restype = ctypes.c_void_p
        self._cf.CFDataGetLength.argtypes = [ctypes.c_void_p]
        self._cf.CFDataGetLength.restype = ctypes.c_long
        self._cf.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
        self._cf.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_uint8)
        self._cf.CFRelease.argtypes = [ctypes.c_void_p]
        self._cf.CFRelease.restype = None
        self._cf.CFDictionaryCreate.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_long,
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        self._cf.CFDictionaryCreate.restype = ctypes.c_void_p
        self._security.SecItemCopyMatching.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self._security.SecItemCopyMatching.restype = ctypes.c_int32
        self._security.SecItemAdd.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self._security.SecItemAdd.restype = ctypes.c_int32
        self._security.SecItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._security.SecItemUpdate.restype = ctypes.c_int32
        self._security.SecItemDelete.argtypes = [ctypes.c_void_p]
        self._security.SecItemDelete.restype = ctypes.c_int32

    def _constant(self, name: str, library=None) -> ctypes.c_void_p:
        lib = library or self._security
        return ctypes.c_void_p.in_dll(lib, name)

    def _string(self, value: str) -> ctypes.c_void_p:
        ref = self._cf.CFStringCreateWithCString(None, value.encode("utf-8"), 0x08000100)
        if not ref:
            raise KeychainError("macOS Keychain operation failed")
        return ctypes.c_void_p(ref)

    def _dict(self, values: list[tuple[ctypes.c_void_p, ctypes.c_void_p]]) -> ctypes.c_void_p:
        count = len(values)
        keys = (ctypes.c_void_p * count)(*(key.value for key, _ in values))
        items = (ctypes.c_void_p * count)(*(value.value for _, value in values))
        ref = self._cf.CFDictionaryCreate(None, keys, items, count, None, None)
        if not ref:
            raise KeychainError("macOS Keychain operation failed")
        return ctypes.c_void_p(ref)

    def _base(self, account: str, refs: list[ctypes.c_void_p]) -> list[tuple[ctypes.c_void_p, ctypes.c_void_p]]:
        if not isinstance(account, str) or not self.ACCOUNT_PATTERN.fullmatch(account):
            raise KeychainError("macOS Keychain operation failed")
        service = self._string(self.service)
        name = self._string(account)
        refs.extend((service, name))
        return [
            (self._constant("kSecClass"), self._constant("kSecClassGenericPassword")),
            (self._constant("kSecAttrService"), service),
            (self._constant("kSecAttrAccount"), name),
            (self._constant("kSecUseAuthenticationUI"),
             self._constant("kSecUseAuthenticationUIFail")),
        ]

    def _release_all(self, refs: list[ctypes.c_void_p]) -> None:
        for ref in reversed(refs):
            if ref and ref.value:
                self._cf.CFRelease(ref)

    def get(self, account: str) -> str | None:
        refs: list[ctypes.c_void_p] = []
        try:
            values = self._base(account, refs)
            values.extend([
                (self._constant("kSecReturnData"), self._constant("kCFBooleanTrue", self._cf)),
                (self._constant("kSecMatchLimit"), self._constant("kSecMatchLimitOne")),
            ])
            query = self._dict(values)
            refs.append(query)
            result = ctypes.c_void_p()
            status = self._security.SecItemCopyMatching(query, ctypes.byref(result))
            if status == self.ERR_ITEM_NOT_FOUND:
                return None
            if status != 0 or not result.value:
                raise KeychainError("macOS Keychain is unavailable or access was denied")
            try:
                size = self._cf.CFDataGetLength(result)
                pointer = self._cf.CFDataGetBytePtr(result)
                raw = ctypes.string_at(pointer, size)
                return raw.decode("utf-8", "strict")
            finally:
                self._cf.CFRelease(result)
        except KeychainError:
            raise
        except Exception:
            raise KeychainError("macOS Keychain is unavailable or access was denied") from None
        finally:
            self._release_all(refs)

    def set(self, account: str, value: str) -> None:
        refs: list[ctypes.c_void_p] = []
        try:
            encoded = value.encode("utf-8", "strict")
            buffer = (ctypes.c_uint8 * len(encoded)).from_buffer_copy(encoded)
            data = ctypes.c_void_p(self._cf.CFDataCreate(None, buffer, len(encoded)))
            if not data.value:
                raise KeychainError("macOS Keychain operation failed")
            refs.append(data)
            query = self._dict(self._base(account, refs))
            refs.append(query)
            attributes = self._dict([
                (self._constant("kSecValueData"), data),
                (self._constant("kSecUseAuthenticationUI"),
                 self._constant("kSecUseAuthenticationUIFail")),
            ])
            refs.append(attributes)
            status = self._security.SecItemUpdate(query, attributes)
            if status == self.ERR_ITEM_NOT_FOUND:
                add_query = self._dict(self._base(account, refs) + [
                    (self._constant("kSecValueData"), data),
                    (self._constant("kSecAttrAccessible"),
                     self._constant("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly")),
                ])
                refs.append(add_query)
                status = self._security.SecItemAdd(add_query, None)
            if status != 0:
                raise KeychainError("macOS Keychain is unavailable or access was denied")
        except KeychainError:
            raise
        except Exception:
            raise KeychainError("macOS Keychain is unavailable or access was denied") from None
        finally:
            self._release_all(refs)

    def delete(self, account: str) -> None:
        refs: list[ctypes.c_void_p] = []
        try:
            query = self._dict(self._base(account, refs))
            refs.append(query)
            status = self._security.SecItemDelete(query)
            if status not in (0, self.ERR_ITEM_NOT_FOUND):
                raise KeychainError("macOS Keychain is unavailable or access was denied")
        except KeychainError:
            raise
        except Exception:
            raise KeychainError("macOS Keychain is unavailable or access was denied") from None
        finally:
            self._release_all(refs)
