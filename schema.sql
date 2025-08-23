-- Users table (for authentication, roles, CRs, etc.)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  username TEXT,
  roll_no TEXT,
  room_no TEXT,
  password TEXT NOT NULL,
  role TEXT NOT NULL,
  class_code TEXT,
  cr_type TEXT,
  cr_elective_id TEXT,
  is_approved BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Classes table (schedule uploaded by CRs)
CREATE TABLE IF NOT EXISTS classes (
  id SERIAL PRIMARY KEY,
  class_code TEXT NOT NULL,
  subject_name TEXT NOT NULL,
  teacher_name TEXT,
  scheduled_at TIMESTAMP NOT NULL,
  is_cancelled BOOLEAN DEFAULT false
);

-- Attendance table (tracking attendance per student per class)
CREATE TABLE IF NOT EXISTS attendance (
  id SERIAL PRIMARY KEY,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  class_id INT REFERENCES classes(id) ON DELETE CASCADE,
  attended BOOLEAN DEFAULT false,
  marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin (only if not exists)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@prezz.com') THEN
    INSERT INTO users (email, username, password, role, is_approved)
    VALUES (
      'admin@prezz.com',
      'admin',
      -- password = "admin123" (bcrypt hash)
      '$2b$10$XGJXb9T3jzZpH2kY/0t8LOxV5kS1Pz7hJcxiacg80QDN3q1QZ6vPC',
      'admin',
      true
    );
  END IF;
END $$;
