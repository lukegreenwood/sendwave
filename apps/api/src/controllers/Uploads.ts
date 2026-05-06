import {Controller, Middleware, Post} from '@overnightjs/core';
import type {NextFunction, Request, Response} from 'express';
import multer, {MulterError} from 'multer';
import signale from 'signale';
import {BadRequest} from '../exceptions/index.js';
import {requireAuth, requireEmailVerified} from '../middleware/auth.js';
import * as S3Service from '../services/S3Service.js';
import {CatchAsync} from '../utils/asyncHandler.js';

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];

const MAGIC_BYTES: Record<string, Buffer[]> = {
  'image/jpeg': [Buffer.from([0xff, 0xd8, 0xff])],
  'image/jpg': [Buffer.from([0xff, 0xd8, 0xff])],
  'image/png': [Buffer.from([0x89, 0x50, 0x4e, 0x47])],
  'image/gif': [Buffer.from('GIF87a'), Buffer.from('GIF89a')],
  'image/webp': [Buffer.from('RIFF')],
};

function validateMagicBytes(buffer: Buffer, mimetype: string): boolean {
  const signatures = MAGIC_BYTES[mimetype];
  if (!signatures) return false;
  return signatures.some(sig => buffer.subarray(0, sig.length).equals(sig));
}

// Configure multer for file uploads (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max file size
  },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      // Surface the offending mimetype so users see e.g. "image/svg+xml" in the response
      cb(new BadRequest(`Unsupported image type "${file.mimetype}". Allowed: JPEG, PNG, GIF, WebP.`));
    }
  },
});

/**
 * Wraps multer middleware so that multer's own errors (LIMIT_FILE_SIZE,
 * LIMIT_UNEXPECTED_FILE, fileFilter rejections, etc.) are converted into
 * 400 BadRequest responses instead of falling through to the generic
 * 500 "Unexpected error occurred" branch in the global error handler.
 */
function uploadSingleImage(req: Request, res: Response, next: NextFunction) {
  upload.single('image')(req, res, err => {
    if (!err) {
      return next();
    }

    if (err instanceof BadRequest) {
      return next(err);
    }

    if (err instanceof MulterError) {
      const messages: Record<string, string> = {
        LIMIT_FILE_SIZE: 'Image is too large. Maximum size is 10 MB.',
        LIMIT_UNEXPECTED_FILE: `Unexpected file field "${err.field ?? ''}". Use the "image" field name.`,
        LIMIT_FILE_COUNT: 'Too many files uploaded.',
        LIMIT_PART_COUNT: 'Too many parts in the multipart upload.',
        LIMIT_FIELD_KEY: 'A field name was too long.',
        LIMIT_FIELD_VALUE: 'A field value was too long.',
        LIMIT_FIELD_COUNT: 'Too many fields in the request.',
      };

      const message = messages[err.code] ?? `Upload failed: ${err.message}`;
      return next(new BadRequest(message, undefined, {multerCode: err.code, field: err.field}));
    }

    // Any other error from the upload middleware is a client-side problem
    // (malformed multipart body, etc.) — surface it as 400, not 500.
    const message = err instanceof Error ? err.message : 'Failed to read uploaded file';
    return next(new BadRequest(message));
  });
}

@Controller('uploads')
export class Uploads {
  /**
   * POST /uploads/image
   * Upload an image file to S3/Minio
   */
  @Post('image')
  @Middleware([requireAuth, requireEmailVerified, uploadSingleImage])
  @CatchAsync
  public async uploadImage(req: Request, res: Response, _next: NextFunction) {
    const auth = res.locals.auth;

    if (!S3Service.isS3Enabled()) {
      return res.status(503).json({
        error: 'File uploads are not enabled. Please configure S3 storage.',
      });
    }

    if (!req.file) {
      throw new BadRequest('No image file provided');
    }

    if (!validateMagicBytes(req.file.buffer, req.file.mimetype)) {
      throw new BadRequest('File contents do not match the declared image type');
    }

    // Upload file to S3/Minio. Wrap in a dedicated try/catch so we can log the
    // full error with upload context (filename, mimetype, size, projectId) and
    // return a sanitized 500 — without masking unrelated server errors that
    // would otherwise be caught by the global handler.
    try {
      const result = await S3Service.uploadFile({
        file: req.file.buffer,
        filename: req.file.originalname,
        contentType: req.file.mimetype,
        projectId: auth.projectId!,
      });

      return res.status(200).json({
        url: result.url,
        key: result.key,
        filename: req.file.originalname,
        contentType: req.file.mimetype,
        size: req.file.size,
      });
    } catch (error) {
      signale.error('[UPLOADS] Failed to upload image to S3', {
        error: error instanceof Error ? {name: error.name, message: error.message, stack: error.stack} : error,
        filename: req.file.originalname,
        contentType: req.file.mimetype,
        size: req.file.size,
        projectId: auth.projectId,
      });

      return res.status(500).json({
        error: 'Failed to upload image. Please try again.',
      });
    }
  }
}
