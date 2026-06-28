-- Add subscription-related columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'inactive';
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_plan VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_start DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_end DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_proof_image BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_proof_mimetype VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_proof_uploaded_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_verified_by INTEGER REFERENCES users(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_verified_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_notes TEXT;

-- Create payment settings table for SuperAdmin
CREATE TABLE IF NOT EXISTS payment_settings (
    id SERIAL PRIMARY KEY,
    bank_name VARCHAR(255),
    account_number VARCHAR(100),
    account_owner VARCHAR(255),
    phone_number VARCHAR(50),
    updated_by INTEGER REFERENCES users(id),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default payment settings
INSERT INTO payment_settings (bank_name, account_number, account_owner, phone_number)
VALUES ('Bank Name', '1234567890', 'Account Owner', '+250 788 888 888')
ON CONFLICT DO NOTHING;
