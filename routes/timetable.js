const express = require('express');
const router = express.Router();
const vision = require('@google-cloud/vision');
const authenticate = require('../middleware/auth');
const multer = require('multer');

const client = new vision.ImageAnnotatorClient();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/process-timetable', authenticate, upload.single('image'), async (req, res) => {
    try {
        const { subjects, timeSlots } = req.body;
        const image = req.file;

        if (!image || !subjects || !timeSlots) {
            return res.status(400).json({ error: 'Missing required fields: image, subjects, timeSlots' });
        }

        const parsedSubjects = JSON.parse(subjects);
        const parsedTimeSlots = JSON.parse(timeSlots);

        console.log('Parsed Subjects:', parsedSubjects);
        console.log('Parsed Time Slots:', parsedTimeSlots);

        // Use Google Cloud Vision API for OCR
        const [result] = await client.textDetection({
            image: { content: image.buffer.toString('base64') },
        });

        const text = result.textAnnotations[0]?.description;
        console.log('Extracted Text:', text);

        if (!text) {
            return res.status(400).json({ error: 'No text detected in the image.' });
        }

        // Parse the extracted text
        const lines = text.split('\n').map(line => line.trim()).filter(line => line);
        console.log('Parsed Lines:', lines);

        const timeSlotRegex = /(\d{1,2}:\d{2}\s*[APMapm]{0,2}\s*-\s*\d{1,2}:\d{2}\s*[APMapm]{0,2})/;
        const firstRow = lines[0].split(/\s+/).filter(cell => cell);
        console.log('First Row:', firstRow);

        const extractedTimeSlots = firstRow.slice(1).map(cell => {
            const match = cell.match(timeSlotRegex);
            return match ? { start_time: match[1].split('-')[0].trim(), end_time: match[1].split('-')[1].trim() } : null;
        }).filter(slot => slot);
        console.log('Extracted Time Slots:', extractedTimeSlots);

        const normalizeTime = (time) => time.replace(/^0/, '').replace(/\s*[APMapm]+/, '');
        const timeSlotMap = {};
        extractedTimeSlots.forEach((slot, index) => {
            const matchingSlot = parsedTimeSlots.find(
                dbSlot => normalizeTime(dbSlot.start_time) === normalizeTime(slot.start_time) &&
                          normalizeTime(dbSlot.end_time) === normalizeTime(slot.end_time)
            );
            if (matchingSlot) {
                timeSlotMap[index] = matchingSlot.id;
            }
        });
        console.log('Time Slot Map:', timeSlotMap);

        const subjectMap = parsedSubjects.reduce((acc, subject) => {
            acc[subject.name.toLowerCase()] = subject.id;
            return acc;
        }, {});
        console.log('Subject Map:', subjectMap);

        const extractedSchedules = [];
        const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
        const dayMapping = {
            'mon': 'Monday', 'monday': 'Monday',
            'tue': 'Tuesday', 'tuesday': 'Tuesday',
            'wed': 'Wednesday', 'wednesday': 'Wednesday',
            'thu': 'Thursday', 'thursday': 'Thursday',
            'fri': 'Friday', 'friday': 'Friday'
        };
        const startDate = '2025-05-26';
        const endDate = '2025-06-30';

        for (let i = 1; i < lines.length && i <= days.length; i++) {
            const row = lines[i].split(/\s+/).filter(cell => cell);
            console.log(`Row ${i} (${days[i-1]}):`, row);
            if (row.length < 2) continue;

            const day = row[0].toLowerCase();
            const normalizedDay = dayMapping[day] || day;
            if (!days.includes(normalizedDay)) continue;

            const subjectsInRow = row.slice(1);
            subjectsInRow.forEach((subjectName, slotIndex) => {
                if (slotIndex >= extractedTimeSlots.length) return;

                const cleanedSubjectName = subjectName.replace(/[^a-zA-Z\s]/g, '').trim().toLowerCase();
                if (!cleanedSubjectName) return;

                const subjectId = subjectMap[cleanedSubjectName] || subjectMap[cleanedSubjectName.replace('s$', '')];
                const timeSlotId = timeSlotMap[slotIndex];
                console.log(`Day: ${normalizedDay}, Slot: ${slotIndex}, Subject: ${cleanedSubjectName}, Subject ID: ${subjectId}, Time Slot ID: ${timeSlotId}`);

                if (subjectId && timeSlotId) {
                    extractedSchedules.push({
                        subject_id: subjectId,
                        day_of_week: normalizedDay,
                        time_slot_id: timeSlotId,
                        start_date: startDate,
                        end_date: endDate,
                    });
                }
            });
        }

        console.log('Extracted Schedules:', extractedSchedules);

        if (extractedSchedules.length === 0) {
            return res.status(400).json({ error: 'No valid schedules extracted from the timetable.' });
        }

        res.status(200).json({ schedules: extractedSchedules, timeSlots: parsedTimeSlots });
    } catch (error) {
        console.error('Error processing timetable:', error);
        if (error.code === 7 && error.message.includes('billing')) {
            return res.status(500).json({ error: 'Billing is not enabled for the Google Cloud project. Please enable billing and try again.' });
        }
        res.status(500).json({ error: error.message || 'Failed to process timetable image.' });
    }
});

module.exports = router;