from typing import List, Dict, Any, Optional
from sqlalchemy import text
from bench_app.database.connection import SessionLocal, Product
from bench_app.utils.validators import validate_order_by


def get_products_vulnerable_order_by(sort_col: str) -> List[Dict[str, Any]]:
    """
    VULN-005: SQL Injection via unvalidated dynamic ORDER BY in raw SQL f-string.
    """
    session = SessionLocal()
    try:
        # // CASE: VULN-005
        query = f"SELECT id, name, price FROM products ORDER BY {sort_col}"
        result = session.execute(text(query)).fetchall()
        return [{"id": r[0], "name": r[1], "price": r[2]} for r in result]
    finally:
        session.close()


def query_tenant_table_dynamic(tenant_table: str) -> List[Dict[str, Any]]:
    """
    VULN-006: SQL Injection via unvalidated dynamic table name interpolation.
    """
    session = SessionLocal()
    try:
        # // CASE: VULN-006
        query = f"SELECT * FROM {tenant_table} WHERE active = 1"
        result = session.execute(text(query)).fetchall()
        return [dict(r._mapping) for r in result]
    finally:
        session.close()


def get_user_by_name_sqlalchemy_text_flaw(username: str) -> List[Dict[str, Any]]:
    """
    VULN-007: SQL Injection inside SQLAlchemy text() construct using direct format interpolation.
    """
    session = SessionLocal()
    try:
        # // CASE: VULN-007
        stmt = text(f"SELECT id, username, email FROM users WHERE username = '{username}'")
        result = session.execute(stmt).fetchall()
        return [{"id": r[0], "username": r[1], "email": r[2]} for r in result]
    finally:
        session.close()


def search_products_unescaped_like(keyword: str) -> List[Dict[str, Any]]:
    """
    VULN-008: SQL Injection via unescaped string formatting in LIKE clause.
    """
    session = SessionLocal()
    try:
        # Direct concatenation or formatting in SQL clause
        # // CASE: VULN-008
        raw_sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{keyword}%'"
        result = session.execute(text(raw_sql)).fetchall()
        return [{"id": r[0], "name": r[1], "price": r[2]} for r in result]
    finally:
        session.close()


def get_products_safe_validated_order_by(user_col: str) -> List[Dict[str, Any]]:
    """
    SAFE-001: Dynamic ORDER BY validated against an Enum whitelist defined in validators.py.
    """
    # Cross-file validation: validators.validate_order_by strictly checks against SortColumn enum
    validated_col = validate_order_by(user_col)
    session = SessionLocal()
    try:
        # // CASE: SAFE-001
        query = f"SELECT id, name, price FROM products ORDER BY {validated_col}"
        result = session.execute(text(query)).fetchall()
        return [{"id": r[0], "name": r[1], "price": r[2]} for r in result]
    finally:
        session.close()


def get_product_by_casted_id(raw_id: Any) -> Optional[Dict[str, Any]]:
    """
    SAFE-002: f-string used in SQL, but target variable is explicitly int() cast right before query.
    """
    # Explicit integer cast guarantees no injection payload can survive
    safe_int_id = int(raw_id)
    session = SessionLocal()
    try:
        # // CASE: SAFE-002
        query = f"SELECT id, name, price FROM products WHERE id = {safe_int_id}"
        row = session.execute(text(query)).fetchone()
        if row:
            return {"id": row[0], "name": row[1], "price": row[2]}
        return None
    finally:
        session.close()


# Static query mapping
SAFE_QUERY_MAPPING = {
    "all": "SELECT id, name, price FROM products",
    "cheap": "SELECT id, name, price FROM products WHERE price < 100",
    "premium": "SELECT id, name, price FROM products WHERE price >= 100",
}


def get_products_from_static_map(filter_mode: str) -> List[Dict[str, Any]]:
    """
    SAFE-015: Query constructed via dictionary lookup of static constant SQL strings.
    No user input is interpolated into the SQL string.
    """
    # // CASE: SAFE-015
    selected_query = SAFE_QUERY_MAPPING.get(filter_mode, SAFE_QUERY_MAPPING["all"])
    session = SessionLocal()
    try:
        result = session.execute(text(selected_query)).fetchall()
        return [{"id": r[0], "name": r[1], "price": r[2]} for r in result]
    finally:
        session.close()
