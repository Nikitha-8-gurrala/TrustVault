
const express = require("express");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

const pool = require("./db");
const { writeAudit } = require("./audit");

const router = express.Router();

const uploadDirectory = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDirectory, { recursive: true });

const allowedTypes = new Set([
  "application/pdf",
  "image/png",
  "image/jpeg",
]);

const storage = multer.diskStorage({
  destination: (req, file, callback) => {
    callback(null, uploadDirectory);
  },
  filename: (req, file, callback) => {
    callback(null, crypto.randomUUID());
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1,
  },
  fileFilter: (req, file, callback) => {
    if (!allowedTypes.has(file.mimetype)) {
      return callback(
        new Error("Only PDF, PNG, and JPEG files are allowed.")
      );
    }

    callback(null, true);
  },
});

async function auditDeniedUpload(req, reason) {
  if (!req.user?.id) return;

  await writeAudit({
    actorId: req.user.id,
    action: "document.upload",
    outcome: "denied",
    details: { reason },
  });
}

function handleUploadError(error, req, res, next) {
  if (!error) return next();

  const status = error instanceof multer.MulterError ? 400 : 400;

  auditDeniedUpload(
    req,
    error instanceof multer.MulterError
      ? "upload_limit_exceeded"
      : "invalid_file_type_or_upload"
  )
    .catch((auditError) => {
      console.error("Failed to audit rejected upload:", auditError.message);
    })
    .finally(() => {
      if (res.headersSent) return;

      return res.status(status).json({
        error:
          error instanceof multer.MulterError
            ? "Upload failed. Maximum file size is 5 MB."
            : error.message,
      });
    });
}

function hasValidSignature(filePath, mimeType) {
  const buffer = fs.readFileSync(filePath);

  if (mimeType === "application/pdf") {
    return buffer.subarray(0, 5).toString() === "%PDF-";
  }

  if (mimeType === "image/png") {
    return buffer.subarray(0, 8).equals(
      Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
    );
  }

  if (mimeType === "image/jpeg") {
    return (
      buffer[0] === 0xff &&
      buffer[1] === 0xd8 &&
      buffer[2] === 0xff
    );
  }

  return false;
}

router.post("/", upload.single("document"), async (req, res) => {
  let savedFilePath;

  try {
    if (!req.file) {
      await auditDeniedUpload(req, "missing_document_file");

      return res.status(400).json({
        error: "A document file is required.",
      });
    }

    savedFilePath = req.file.path;

    if (!hasValidSignature(savedFilePath, req.file.mimetype)) {
      fs.unlinkSync(savedFilePath);
      savedFilePath = null;

      await auditDeniedUpload(req, "file_signature_mismatch");

      return res.status(400).json({
        error: "File contents do not match the allowed file type.",
      });
    }

    const { name, category } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof category !== "string" ||
      !category.trim()
    ) {
      fs.unlinkSync(savedFilePath);
      savedFilePath = null;

      await auditDeniedUpload(req, "missing_name_or_category");

      return res.status(400).json({
        error: "Document name and category are required.",
      });
    }

    const result = await pool.query(
      `INSERT INTO documents
        (owner_id, name, category, storage_path, mime_type, size_bytes)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, owner_id, name, category, created_at`,
      [
        req.user.id,
        name.trim(),
        category.trim(),
        req.file.filename,
        req.file.mimetype,
        req.file.size,
      ]
    );

    await writeAudit({
      actorId: req.user.id,
      action: "document.upload",
      documentId: result.rows[0].id,
      outcome: "success",
      details: {
        mimeType: req.file.mimetype,
        sizeBytes: req.file.size,
      },
    });

    return res.status(201).json({
      message: "Document uploaded successfully.",
      document: result.rows[0],
    });
  } catch (error) {
    if (savedFilePath && fs.existsSync(savedFilePath)) {
      try {
        fs.unlinkSync(savedFilePath);
      } catch (cleanupError) {
        console.error("Upload cleanup failed:", cleanupError.message);
      }
    }

    try {
      await auditDeniedUpload(req, "upload_processing_failed");
    } catch (auditError) {
      console.error("Failed to audit upload error:", auditError.message);
    }

    console.error("Document upload failed:", error.message);

    if (!res.headersSent) {
      return res.status(500).json({
        error: "Unable to upload document.",
      });
    }
  }
});

router.use(handleUploadError);

module.exports = router;
