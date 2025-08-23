const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const Joi = require('joi');
const sanitizeFilename = require('sanitize-filename');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, '../Uploads');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const sanitizedName = sanitizeFilename(file.originalname);
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `${uniqueSuffix}-${sanitizedName}`);
  }
});
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const fileTypes = /\.(pdf|jpeg|jpg|png)$/i;
    const mimeTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png'];
    const extname = fileTypes.test(path.extname(file.originalname));
    const mimetype = mimeTypes.includes(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only PDFs and images (jpeg, jpg, png) are allowed'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});

const restrictTo = (roles) => (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized: No user authenticated' });
  }
  const userRole = req.user.role?.toUpperCase();
  if (!userRole || !roles.map(r => r.toUpperCase()).includes(userRole)) {
    return res.status(403).json({ error: `Unauthorized: Only ${roles.join(' or ')} can access this route` });
  }
  next();
};

router.get('/categories/:subjectId', async (req, res) => {
  const { subjectId } = req.params;
  try {
    let query;
    let params;
    if (subjectId.startsWith('elective_')) {
      const numericId = parseInt(subjectId.split('_')[1], 10);
      if (isNaN(numericId)) {
        return res.status(400).json({ error: 'Invalid elective ID format' });
      }
      query = 'SELECT * FROM categories WHERE elective_id = $1';
      params = [numericId];
    } else {
      const numericId = parseInt(subjectId, 10);
      if (isNaN(numericId)) {
        return res.status(400).json({ error: 'Subject ID must be a number' });
      }
      query = 'SELECT * FROM categories WHERE subject_id = $1';
      params = [numericId];
    }
    const categories = await pool.query(query, params);
    res.json(categories.rows);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ error: 'Failed to fetch categories', details: error.message });
  }
});

router.post('/upload', restrictTo(['STUDENT', 'CR']), upload.single('file'), async (req, res) => {
  try {
    let { classcode, elective_id, subject_id, url, category_id } = req.body;
    const file = req.file;
    const user = req.user;

    // Enhanced debug logging
    console.log('=== UPLOAD REQUEST DEBUG ===');
    console.log('Raw req.body:', req.body);
    console.log('User info:', {
      id: user.id,
      cr_type: user.cr_type,
      cr_elective_id: user.cr_elective_id,
      class_code: user.class_code
    });
    console.log('Request data:', { classcode, elective_id, subject_id, url, category_id, filePresent: !!file });

    // Fix for Issue 1: Convert empty string elective_id to null
    elective_id = elective_id === '' ? null : elective_id;
    subject_id = subject_id === '' ? null : subject_id;

    const parsedElectiveId = elective_id ? parseInt(elective_id, 10) : null;
    const parsedSubjectId = subject_id ? parseInt(subject_id, 10) : null;
    const parsedCategoryId = category_id ? parseInt(category_id, 10) : null;

    console.log('Parsed values:', { parsedElectiveId, parsedSubjectId, parsedCategoryId });

    const validationData = {
      ...(classcode && { classcode }),
      ...(parsedElectiveId !== null && { elective_id: parsedElectiveId }),
      ...(parsedSubjectId !== null && { subject_id: parsedSubjectId }),
      ...(url && { url }),
      category_id: parsedCategoryId
    };

    const schema = Joi.object({
      classcode: Joi.string().min(6).max(6).optional(),
      elective_id: Joi.number().integer().optional(),
      subject_id: Joi.number().integer().optional(),
      url: Joi.string().uri().optional(),
      category_id: Joi.number().integer().required()
    });

    const { error } = schema.validate(validationData);
    if (error) {
      console.log('Validation error:', error.details[0]);
      return res.status(400).json({ error: error.details[0].message });
    }

    if (!file && !url) {
      return res.status(400).json({ error: 'Either a file or a URL is required' });
    }
    if (file && url) {
      return res.status(400).json({ error: 'Provide either a file or a URL, not both' });
    }

    const isElectiveUpload = parsedElectiveId !== null;

    if (isElectiveUpload) {
      if (!parsedElectiveId) {
        return res.status(400).json({ error: 'elective_id is required for elective uploads' });
      }
      console.log('Processing as ELECTIVE upload');
    } else {
      if (!classcode || !parsedSubjectId) {
        return res.status(400).json({ error: 'classcode and subject_id are required for regular subject uploads' });
      }
      console.log('Processing as REGULAR SUBJECT upload');
    }

    if (user.cr_type === 'elective') {
      if (!parsedElectiveId || parsedElectiveId !== user.cr_elective_id) {
        return res.status(403).json({ error: 'You can only upload materials for your assigned elective' });
      }
      const electiveCheck = await pool.query('SELECT id FROM electives WHERE id = $1', [parsedElectiveId]);
      if (electiveCheck.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid elective ID' });
      }
    } else if (user.cr_type === 'regular') {
      if (classcode !== user.class_code) {
        return res.status(403).json({ error: 'You can only upload materials for your class' });
      }
      const subjectCheck = await pool.query('SELECT id FROM subjects WHERE id = $1 AND classcode = $2', [parsedSubjectId, classcode]);
      if (subjectCheck.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid subject for this class' });
      }
    }

    let categoryCheck;
    if (isElectiveUpload) {
      categoryCheck = await pool.query('SELECT id FROM categories WHERE id = $1 AND elective_id = $2', [parsedCategoryId, parsedElectiveId]);
    } else {
      categoryCheck = await pool.query('SELECT id FROM categories WHERE id = $1 AND subject_id = $2', [parsedCategoryId, parsedSubjectId]);
    }

    if (categoryCheck.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid category for this subject or elective' });
    }

    const newMaterial = await pool.query(
      `INSERT INTO materials 
       (filename, path, url, class_code, elective_id, subject_id, category_id, uploaded_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        file ? sanitizeFilename(file.originalname) : null,
        file ? file.path : null,
        url || null,
        classcode || null,
        parsedElectiveId,
        parsedSubjectId,
        parsedCategoryId,
        user.id
      ]
    );

    console.log('Uploaded material:', newMaterial.rows[0]);
    res.status(201).json({ message: 'Material uploaded successfully', material: newMaterial.rows[0] });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload material', details: error.message });
  }
});

router.post('/categories', restrictTo(['CR']), async (req, res) => {
  const { name, subject_id, elective_id } = req.body;
  try {
    const schema = Joi.object({
      name: Joi.string().min(3).required(),
      subject_id: Joi.number().integer().optional().allow(null),
      elective_id: Joi.number().integer().optional().allow(null)
    });
    const { error } = schema.validate({ name, subject_id, elective_id });
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const newCategory = await pool.query(
      'INSERT INTO categories (name, subject_id, elective_id, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, subject_id || null, elective_id || null, req.user.id]
    );

    res.status(201).json(newCategory.rows[0]);
  } catch (error) {
    console.error('Category creation error:', error);
    res.status(500).json({ error: 'Failed to create category', details: error.message });
  }
});

router.get('/', async (req, res) => {
  try {
    const classCode = req.user.class_code;
    const userId = req.user.id;
    const isCr = req.user.is_cr ?? req.user.role?.toUpperCase() === 'CR'; // fallback
    const crType = req.user.cr_type;
    const crElectiveId = req.user.cr_elective_id;

    console.log('User context:', req.user);

    let query = `
      SELECT m.*, COALESCE(s.name, e.name) AS subject_name, u.username AS uploaded_by_name
      FROM materials m
      LEFT JOIN subjects s ON m.subject_id = s.id
      LEFT JOIN electives e ON m.elective_id = e.id
      LEFT JOIN users u ON m.uploaded_by = u.id
      WHERE m.classcode = $1
    `;
    const parsedElectiveId = parseInt(crElectiveId, 10);
    let params = [classCode];

    if (isCr && crType === 'elective' && Number.isInteger(parseInt(crElectiveId))) {
      query = `
        SELECT m.*, COALESCE(s.name, e.name) AS subject_name, u.username AS uploaded_by_name
        FROM materials m
        LEFT JOIN subjects s ON m.subject_id = s.id
        LEFT JOIN electives e ON m.elective_id = e.id
        LEFT JOIN users u ON m.uploaded_by = u.id
        WHERE m.elective_id = $1
      `;
      params = [parsedElectiveId]; // ✅ parsed to number
    } else if (!isCr) {
      query += `
        OR m.elective_id IN (
          SELECT elective_id FROM student_electives WHERE student_id = $2 AND status = 'enrolled'
        )
      `;
      params.push(userId);
    }

    const materials = await pool.query(query, params);
    console.log('Retrieved materials:', materials.rows);
    res.json(materials.rows);
  } catch (err) {
    console.error('Error retrieving materials:', err);
    res.status(500).json({ error: 'Failed to retrieve materials', details: err.message });
  }
});

router.delete('/:id', restrictTo(['CR']), async (req, res) => {
  const { id } = req.params;
  try {
    const material = await pool.query('SELECT * FROM materials WHERE id = $1', [id]);
    if (material.rows.length === 0) {
      return res.status(404).json({ error: 'Material not found' });
    }
    if (Number(material.rows[0].uploaded_by) !== Number(req.user.id)) {
      return res.status(403).json({ error: 'You can only delete materials you uploaded' });
    }
    if (material.rows[0].path) {
      const filePath = path.join(__dirname, '..', material.rows[0].path);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
    await pool.query('DELETE FROM materials WHERE id = $1', [id]);
    res.json({ message: 'Material deleted successfully' });
  } catch (error) {
    console.error('Error deleting material:', error);
    res.status(500).json({ error: 'Failed to delete material', details: error.message });
  }
});

router.put('/:id', restrictTo(['CR']), async (req, res) => {
  const { id } = req.params;
  const { filename } = req.body;
  try {
    const schema = Joi.object({
      filename: Joi.string().min(3).required(),
    });
    const { error } = schema.validate({ filename });
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
    const material = await pool.query('SELECT * FROM materials WHERE id = $1', [id]);
    if (material.rows.length === 0) {
      return res.status(404).json({ error: 'Material not found' });
    }
    if (material.rows[0].uploaded_by !== req.user.id) {
      return res.status(403).json({ error: 'You can only edit materials you uploaded' });
    }
    const updatedMaterial = await pool.query(
      'UPDATE materials SET filename = $1 WHERE id = $2 RETURNING *',
      [sanitizeFilename(filename), id]
    );
    res.json(updatedMaterial.rows[0]);
  } catch (error) {
    console.error('Error editing material:', error);
    res.status(500).json({ error: 'Failed to edit material', details: error.message });
  }
});

module.exports = router;