"""add 2fa fields to users

Revision ID: 7008568fb5c2
Revises: cfec7a2f8b99
Create Date: 2026-10-02 14:33:52.466555

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7008568fb5c2'
down_revision: Union[str, Sequence[str], None] = 'cfec7a2f8b99'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


mfa_method_enum = sa.Enum('TOTP', 'EMAIL', 'SMS', 'NONE', name='mfa_method_enum')


def upgrade() -> None:
    """Upgrade schema."""
    mfa_method_enum.create(op.get_bind(), checkfirst=True)
    op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column('users', sa.Column('mfa_method', mfa_method_enum, nullable=True))
    op.add_column('users', sa.Column('mfa_secret', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column('mfa_recovery_codes', sa.ARRAY(sa.String()), server_default='{}', nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'mfa_recovery_codes')
    op.drop_column('users', 'mfa_secret')
    op.drop_column('users', 'mfa_method')
    op.drop_column('users', 'mfa_enabled')
    mfa_method_enum.drop(op.get_bind(), checkfirst=True)
