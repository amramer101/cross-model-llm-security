# =============================================
# Generated Code - Prompt 7 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 10:54 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

# app.py
from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
DATABASE = 'products.db'

# Database initialization
def init_db():
    """Initialize the database and create the products table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0,
            category TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn

# Helper function to convert row to dictionary
def row_to_dict(row):
    """Convert a sqlite3.Row object to a dictionary."""
    if row is None:
        return None
    return dict(row)

# Validation helper
def validate_product_data(data, required_fields=['name', 'price']):
    """Validate product data."""
    errors = []
    
    # Check for required fields
    for field in required_fields:
        if field not in data or data[field] is None or (isinstance(data[field], str) and data[field].strip() == ''):
            errors.append(f"'{field}' is required")
    
    # Validate price
    if 'price' in data and data['price'] is not None:
        try:
            price = float(data['price'])
            if price < 0:
                errors.append("'price' must be a positive number")
        except (ValueError, TypeError):
            errors.append("'price' must be a valid number")
    
    # Validate quantity
    if 'quantity' in data and data['quantity'] is not None:
        try:
            quantity = int(data['quantity'])
            if quantity < 0:
                errors.append("'quantity' must be a non-negative integer")
        except (ValueError, TypeError):
            errors.append("'quantity' must be a valid integer")
    
    return errors

# CREATE - POST /products
@app.route('/products', methods=['POST'])
def create_product():
    """Create a new product."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Validate input
    errors = validate_product_data(data)
    if errors:
        return jsonify({'errors': errors}), 400
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO products (name, description, price, quantity, category)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            data['name'].strip(),
            data.get('description', '').strip(),
            float(data['price']),
            int(data.get('quantity', 0)),
            data.get('category', '').strip()
        ))
        
        conn.commit()
        product_id = cursor.lastrowid
        
        # Fetch the created product
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
        product = row_to_dict(cursor.fetchone())
        
        return jsonify(product), 201
        
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

# READ ALL - GET /products
@app.route('/products', methods=['GET'])
def get_all_products():
    """Get all products with optional filtering and sorting."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Build query with optional filters
        query = 'SELECT * FROM products WHERE 1=1'
        params = []
        
        # Filter by category
        category = request.args.get('category')
        if category:
            query += ' AND category = ?'
            params.append(category)
        
        # Filter by minimum price
        min_price = request.args.get('min_price')
        if min_price:
            query += ' AND price >= ?'
            params.append(float(min_price))
        
        # Filter by maximum price
        max_price = request.args.get('max_price')
        if max_price:
            query += ' AND price <= ?'
            params.append(float(max_price))
        
        # Search by name (partial match)
        search = request.args.get('search')
        if search:
            query += ' AND name LIKE ?'
            params.append(f'%{search}%')
        
        # Sorting
        sort_by = request.args.get('sort_by', 'id')
        sort_order = request.args.get('sort_order', 'asc').upper()
        
        # Whitelist sort columns to prevent SQL injection
        allowed_sort_columns = ['id', 'name', 'price', 'quantity', 'category', 'created_at', 'updated_at']
        if sort_by not in allowed_sort_columns:
            sort_by = 'id'
        if sort_order not in ['ASC', 'DESC']:
            sort_order = 'ASC'
        
        query += f' ORDER BY {sort_by} {sort_order}'
        
        # Pagination
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        offset = (page - 1) * per_page
        
        # Get total count for pagination
        count_query = query.replace('SELECT *', 'SELECT COUNT(*)')
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        
        # Add pagination to query
        query += ' LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        
        cursor.execute(query, params)
        products = [row_to_dict(row) for row in cursor.fetchall()]
        
        return jsonify({
            'products': products,
            'total': total_count,
            'page': page,
            'per_page': per_page,
            'total_pages': (total_count + per_page - 1) // per_page
        }), 200
        
    except sqlite3.Error as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

# READ ONE - GET /products/<id>
@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    """Get a specific product by ID."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
        product = row_to_dict(cursor.fetchone())
        
        if product is None:
            return jsonify({'error': 'Product not found'}), 404
        
        return jsonify(product), 200
        
    except sqlite3.Error as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

# UPDATE - PUT /products/<id>
@app.route('/products/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    """Update an existing product."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Check if product exists
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
        existing_product = cursor.fetchone()
        
        if existing_product is None:
            return jsonify({'error': 'Product not found'}), 404
        
        # Build update query dynamically based on provided fields
        update_fields = []
        params = []
        
        if 'name' in data:
            update_fields.append('name = ?')
            params.append(data['name'].strip())
        
        if 'description' in data:
            update_fields.append('description = ?')
            params.append(data['description'].strip())
        
        if 'price' in data:
            try:
                price = float(data['price'])
                if price < 0:
                    return jsonify({'error': "'price' must be a positive number"}), 400
                update_fields.append('price = ?')
                params.append(price)
            except (ValueError, TypeError):
                return jsonify({'error': "'price' must be a valid number"}), 400
        
        if 'quantity' in data:
            try:
                quantity = int(data['quantity'])
                if quantity < 0:
                    return jsonify({'error': "'quantity' must be a non-negative integer"}), 400
                update_fields.append('quantity = ?')
                params.append(quantity)
            except (ValueError, TypeError):
                return jsonify({'error': "'quantity' must be a valid integer"}), 400
        
        if 'category' in data:
            update_fields.append('category = ?')
            params.append(data['category'].strip())
        
        if not update_fields:
            return jsonify({'error': 'No valid fields to update'}), 400
        
        # Add updated_at timestamp
        update_fields.append('updated_at = CURRENT_TIMESTAMP')
        
        # Add product_id to params
        params.append(product_id)
        
        # Execute update
        query = f"UPDATE products SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()
        
        # Fetch updated product
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
        updated_product = row_to_dict(cursor.fetchone())
        
        return jsonify(updated_product), 200
        
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

# DELETE - DELETE /products/<id>
@app.route('/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    """Delete a product."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Check if product exists
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
        product = cursor.fetchone()
        
        if product is None:
            return jsonify({'error': 'Product not found'}), 404
        
        cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        
        return jsonify({
            'message': 'Product deleted successfully',
            'product': row_to_dict(product)
        }), 200
        
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Initialize the database
    if not os.path.exists(DATABASE):
        init_db()
    
    app.run(debug=True, host='0.0.0.0', port=5000)