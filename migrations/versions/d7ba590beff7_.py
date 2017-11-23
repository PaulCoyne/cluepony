"""empty message

Revision ID: d7ba590beff7
Revises: 2254fad1a3aa
Create Date: 2017-11-23 13:33:26.718498

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd7ba590beff7'
down_revision = '2254fad1a3aa'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('admin', sa.Boolean(), nullable=False))
    op.add_column('users', sa.Column('confirmed', sa.Boolean(), nullable=False))
    op.add_column('users', sa.Column('confirmed_on', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('registered_on', sa.DateTime(), nullable=False))
    op.create_unique_constraint(None, 'users', ['email'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.drop_column('users', 'registered_on')
    op.drop_column('users', 'confirmed_on')
    op.drop_column('users', 'confirmed')
    op.drop_column('users', 'admin')
    # ### end Alembic commands ###
