"""empty message

Revision ID: b2f45ceb39c1
Revises: ef22dd6df3a8
Create Date: 2016-03-26 00:51:52.737097

"""

# revision identifiers, used by Alembic.
revision = 'b2f45ceb39c1'
down_revision = 'ef22dd6df3a8'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('avatar_hash', sa.String(length=32), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'avatar_hash')
    ### end Alembic commands ###
