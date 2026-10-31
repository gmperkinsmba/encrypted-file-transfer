class FakeKeychain:
    """Isolated store for tests; values never appear in test output."""
    def __init__(self):
        self.values = {}
        self.fail_set = set()
        self.wrong_read = set()
        self.fail_delete = set()
        self.operations = []

    def get(self, account):
        self.operations.append(("get", account))
        if account in self.wrong_read or account.split("-", 1)[0] in self.wrong_read:
            return "mismatch"
        return self.values.get(account)

    def set(self, account, value):
        self.operations.append(("set", account))
        if account in self.fail_set or account.split("-", 1)[0] in self.fail_set:
            raise RuntimeError("synthetic keychain set failure")
        self.values[account] = value

    def delete(self, account):
        self.operations.append(("delete", account))
        if account in self.fail_delete or account.split("-", 1)[0] in self.fail_delete:
            raise RuntimeError("synthetic keychain delete failure")
        self.values.pop(account, None)
