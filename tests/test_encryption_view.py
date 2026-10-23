"""Real Tk safety confirmations never approve identities by default."""
import gc
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import tkinter as tk
import unittest
from unittest.mock import Mock, patch

from chatroom_client.e2ee_crypto import Identity, bundle_fingerprint
from chatroom_client.encryption_view import EncryptionWindow, confirm_roster, import_keys
from chatroom_client.key_vault import VaultExistsError


class EncryptionViewTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.identity = Identity.generate()
        self.bundle = self.identity.public_bundle()

    def tearDown(self):
        self.root.destroy()
        gc.collect()

    def descendants(self, widget):
        for child in widget.winfo_children():
            yield child
            yield from self.descendants(child)

    def test_group_roster_close_is_rejection(self):
        self.root.after(20, lambda: self.root.winfo_children()[0].destroy())
        self.assertFalse(confirm_roster(self.root, 'team', {'alice': self.bundle}, None))

    def test_group_roster_requires_explicit_checkbox_before_confirmation(self):
        observed = []

        def approve():
            widgets = list(self.descendants(self.root))
            button = next(widget for widget in widgets if isinstance(widget, tk.Button)
                          and widget.cget('text') == '确认接收人')
            observed.append(str(button.cget('state')))
            check = next(widget for widget in widgets if isinstance(widget, tk.Checkbutton))
            check.invoke()
            observed.append(str(button.cget('state')))
            button.invoke()

        self.root.after(20, approve)
        self.assertTrue(confirm_roster(self.root, '团队🙂', {'alice': self.bundle}, None))
        self.assertEqual(observed, ['disabled', 'normal'])

    def test_contact_verification_requires_out_of_band_confirmation(self):
        encryption = SimpleNamespace(status='ready', fingerprint=self.identity.fingerprint,
                                     peers=lambda: [{'username': 'bob', 'fingerprint': bundle_fingerprint(self.bundle),
                                                     'verified': False}], peer_change=lambda name: None)
        controller = SimpleNamespace(encryption=encryption, verify_encryption_peer=Mock())
        view = SimpleNamespace(master=self.root, controller=controller, refresh_encryption=Mock())
        window = EncryptionWindow(view)
        window.tree.selection_set('bob')
        with patch('chatroom_client.encryption_view.messagebox.askyesno', return_value=False) as ask:
            window.verify_peer()
        controller.verify_encryption_peer.assert_not_called()
        self.assertEqual(ask.call_args.kwargs['default'], 'no')
        with patch('chatroom_client.encryption_view.messagebox.askyesno', return_value=True):
            window.verify_peer()
        controller.verify_encryption_peer.assert_called_once_with('bob', bundle_fingerprint(self.bundle))

    def test_contact_verification_passes_the_fingerprint_displayed_before_confirmation(self):
        fingerprint = self.identity.fingerprint
        peer = {'username': 'bob', 'fingerprint': fingerprint, 'verified': False}
        encryption = SimpleNamespace(status='ready', fingerprint=fingerprint,
                                     peers=lambda: [dict(peer)], peer_change=lambda name: None)
        controller = SimpleNamespace(encryption=encryption, verify_encryption_peer=Mock())
        view = SimpleNamespace(master=self.root, controller=controller, refresh_encryption=Mock())
        window = EncryptionWindow(view)
        window.tree.selection_set('bob')

        def confirm(*args, **kwargs):
            peer['fingerprint'] = Identity.generate().fingerprint
            return True

        with patch('chatroom_client.encryption_view.messagebox.askyesno', side_effect=confirm):
            window.verify_peer()
        controller.verify_encryption_peer.assert_called_once_with('bob', fingerprint)

    def test_import_is_blocked_during_an_active_connection(self):
        controller = SimpleNamespace(connection=SimpleNamespace(running=True, auth_busy=False), reconnecting=False)
        view = SimpleNamespace(master=self.root, controller=controller, show_error=Mock())
        with patch('chatroom_client.encryption_view.filedialog.askopenfilename') as choose:
            import_keys(view)
        choose.assert_not_called()
        view.show_error.assert_called_once()

    def test_backup_endpoint_migration_requires_explicit_confirmation(self):
        controller = SimpleNamespace(connection=SimpleNamespace(running=False, auth_busy=False,
                                     settings=SimpleNamespace(host='localhost')), reconnecting=False,
                                     import_encryption_keys=Mock())
        view = SimpleNamespace(master=self.root, controller=controller, show_error=Mock(), notify=Mock(),
                               read_port=lambda: 12346, encryption_passphrase=lambda: 'independent local phrase')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'backup.json'
            path.write_text(json.dumps({'scope': {'endpoint': ['localhost', 12345], 'username': 'alice'}}))
            with patch('chatroom_client.encryption_view.filedialog.askopenfilename', return_value=str(path)), \
                    patch('chatroom_client.encryption_view.messagebox.askyesno', return_value=False):
                import_keys(view)
            controller.import_encryption_keys.assert_not_called()
            with patch('chatroom_client.encryption_view.filedialog.askopenfilename', return_value=str(path)), \
                    patch('chatroom_client.encryption_view.messagebox.askyesno', return_value=True):
                import_keys(view)
            controller.import_encryption_keys.assert_called_once_with(str(path), 'independent local phrase', allow_rebind=True)

    def test_existing_vault_restore_requires_explicit_overwrite_after_validation(self):
        controller = SimpleNamespace(connection=SimpleNamespace(running=False, auth_busy=False,
                                     settings=SimpleNamespace(host='localhost')), reconnecting=False,
                                     import_encryption_keys=Mock(side_effect=[VaultExistsError('already exists'), None]))
        view = SimpleNamespace(master=self.root, controller=controller, show_error=Mock(), notify=Mock(),
                               read_port=lambda: 12345, encryption_passphrase=lambda: 'independent local phrase')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'backup.json'
            path.write_text(json.dumps({'scope': {'endpoint': ['localhost', 12345], 'username': 'alice'}}))
            with patch('chatroom_client.encryption_view.filedialog.askopenfilename', return_value=str(path)), \
                    patch('chatroom_client.encryption_view.messagebox.askyesno', return_value=True) as ask:
                import_keys(view)
            self.assertEqual(controller.import_encryption_keys.call_count, 2)
            self.assertTrue(controller.import_encryption_keys.call_args.kwargs['replace'])
            self.assertEqual(ask.call_args.kwargs['default'], 'no')


if __name__ == '__main__':
    unittest.main()
