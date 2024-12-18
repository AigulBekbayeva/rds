"""Added new column KPO

Revision ID: 5d7e087a93e9
Revises: 4ef69132865d
Create Date: 2024-11-27 17:27:52.472853

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5d7e087a93e9'
down_revision = '4ef69132865d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('fires', schema=None) as batch_op:
        batch_op.add_column(sa.Column('KPO', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('fires', schema=None) as batch_op:
        batch_op.drop_column('KPO')

    # ### end Alembic commands ###
