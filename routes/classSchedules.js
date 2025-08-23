const express = require('express');
const router = express.Router();
const ClassSchedule = require('../models/ClassSchedule'); // Adjust path as needed
const authenticate = require('../middleware/auth'); // Adjust path as needed

// Existing routes...

// Bulk create class schedules
router.post('/bulk', authenticate, async (req, res) => {
    try {
        const schedules = req.body;
        if (!Array.isArray(schedules)) {
            return res.status(400).json({ error: 'Expected an array of schedules' });
        }

        const newSchedules = await ClassSchedule.insertMany(schedules);
        res.status(201).json(newSchedules);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;