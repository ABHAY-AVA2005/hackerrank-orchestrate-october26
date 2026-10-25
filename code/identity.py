"""
Identity resolution module for Deletion-Audit Agent.
Resolves user requests to user_id and current/historical emails, phones, and hashes.
"""
from typing import Dict, List, Optional, Set
import csv

class IdentityResolver:
    def __init__(self, user_identities_path: str, user_audit_log_path: str):
        self.users: Dict[str, dict] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self.historical_email_to_uid: Dict[str, str] = {}
        self.user_all_emails: Dict[str, Set[str]] = {}
        
        # Load user identities
        with open(user_identities_path, 'r', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                uid = row['user_id']
                self.users[uid] = row
                email = row['email'].strip().lower() if row.get('email') else ''
                phone = row['phone'].strip() if row.get('phone') else ''
                ehash = row['email_hash'].strip() if row.get('email_hash') else ''
                
                if email:
                    self.email_to_uid[email] = uid
                    self.user_all_emails.setdefault(uid, set()).add(email)
                if phone:
                    self.phone_to_uid[phone] = uid
                if ehash:
                    self.hash_to_uid[ehash] = uid

        # Load user audit log for historical aliases
        with open(user_audit_log_path, 'r', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                uid = row['user_id']
                field = row['field_name']
                old_val = row['old_value'].strip() if row.get('old_value') else ''
                new_val = row['new_value'].strip() if row.get('new_value') else ''
                
                if field == 'email':
                    if old_val:
                        self.historical_email_to_uid[old_val.lower()] = uid
                        self.user_all_emails.setdefault(uid, set()).add(old_val.lower())
                    if new_val:
                        self.historical_email_to_uid[new_val.lower()] = uid
                        self.user_all_emails.setdefault(uid, set()).add(new_val.lower())

    def resolve(self, email: Optional[str] = None, phone: Optional[str] = None) -> Optional[str]:
        """Resolves an email or phone to a user_id."""
        if email:
            norm_email = email.strip().lower()
            if norm_email in self.email_to_uid:
                return self.email_to_uid[norm_email]
            if norm_email in self.historical_email_to_uid:
                return self.historical_email_to_uid[norm_email]
        if phone:
            norm_phone = phone.strip()
            if norm_phone in self.phone_to_uid:
                return self.phone_to_uid[norm_phone]
        return None

    def get_all_emails(self, user_id: str) -> Set[str]:
        """Returns all known current and past emails for a user_id."""
        return self.user_all_emails.get(user_id, set())

    def get_user_profile(self, user_id: str) -> Optional[dict]:
        return self.users.get(user_id)
