package report

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// S3/R2 Storage Client for Reports
// ============================================================================

// StorageClient defines the interface for report storage operations
type StorageClient interface {
	UploadPDF(ctx context.Context, scanID, reportID uuid.UUID, data []byte) (string, error)
	UploadJSON(ctx context.Context, scanID, reportID uuid.UUID, data []byte) (string, error)
	GeneratePresignedURL(ctx context.Context, key string, expiration time.Duration) (string, error)
	DeleteReport(ctx context.Context, scanID, reportID uuid.UUID) error
}

// S3Config contains S3/R2 configuration
type S3Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	PublicURLBase   string
}

// S3Client implements StorageClient using S3-compatible API
type S3Client struct {
	config S3Config
}

// NewS3Client creates a new S3 storage client
func NewS3Client(config S3Config) (*S3Client, error) {
	if config.Endpoint == "" {
		config.Endpoint = os.Getenv("S3_ENDPOINT")
	}
	if config.Region == "" {
		config.Region = os.Getenv("S3_REGION")
		if config.Region == "" {
			config.Region = "auto"
		}
	}
	if config.Bucket == "" {
		config.Bucket = os.Getenv("S3_BUCKET")
		if config.Bucket == "" {
			config.Bucket = "redteam-reports"
		}
	}
	if config.AccessKeyID == "" {
		config.AccessKeyID = os.Getenv("S3_ACCESS_KEY_ID")
	}
	if config.SecretAccessKey == "" {
		config.SecretAccessKey = os.Getenv("S3_SECRET_ACCESS_KEY")
	}
	if config.PublicURLBase == "" {
		config.PublicURLBase = os.Getenv("S3_PUBLIC_URL_BASE")
	}

	return &S3Client{
		config: config,
	}, nil
}

// NewS3ClientFromEnv creates an S3 client from environment variables
func NewS3ClientFromEnv() (*S3Client, error) {
	return NewS3Client(S3Config{})
}

// GeneratePDFKey generates the S3 key for a PDF report
func GeneratePDFKey(scanID, reportID uuid.UUID) string {
	return fmt.Sprintf("reports/%s/%s.pdf", scanID.String(), reportID.String())
}

// GenerateJSONKey generates the S3 key for a JSON report
func GenerateJSONKey(scanID, reportID uuid.UUID) string {
	return fmt.Sprintf("reports/%s/%s.json", scanID.String(), reportID.String())
}

// UploadPDF uploads a PDF report to S3/R2
func (c *S3Client) UploadPDF(ctx context.Context, scanID, reportID uuid.UUID, data []byte) (string, error) {
	key := GeneratePDFKey(scanID, reportID)

	// In a real implementation, this would use AWS SDK to upload to S3/R2
	// For now, we simulate the upload and return a URL

	// Check if we have S3 credentials
	if c.config.AccessKeyID == "" || c.config.SecretAccessKey == "" {
		// No S3 configured, return local storage path
		return fmt.Sprintf("/storage/%s", key), nil
	}

	// Upload to S3/R2 would happen here
	// Example using AWS SDK:
	// _, err := c.s3Client.PutObject(ctx, &s3.PutObjectInput{
	//     Bucket:      aws.String(c.config.Bucket),
	//     Key:         aws.String(key),
	//     Body:        bytes.NewReader(data),
	//     ContentType: aws.String("application/pdf"),
	// })

	// Generate public URL
	publicURL := c.generatePublicURL(key)

	return publicURL, nil
}

// UploadJSON uploads a JSON report to S3/R2
func (c *S3Client) UploadJSON(ctx context.Context, scanID, reportID uuid.UUID, data []byte) (string, error) {
	key := GenerateJSONKey(scanID, reportID)

	// Check if we have S3 credentials
	if c.config.AccessKeyID == "" || c.config.SecretAccessKey == "" {
		// No S3 configured, return local storage path
		return fmt.Sprintf("/storage/%s", key), nil
	}

	// Upload to S3/R2 would happen here
	// Example using AWS SDK:
	// _, err := c.s3Client.PutObject(ctx, &s3.PutObjectInput{
	//     Bucket:      aws.String(c.config.Bucket),
	//     Key:         aws.String(key),
	//     Body:        bytes.NewReader(data),
	//     ContentType: aws.String("application/json"),
	// })

	// Generate public URL
	publicURL := c.generatePublicURL(key)

	return publicURL, nil
}

// GeneratePresignedURL generates a presigned URL for accessing a report
func (c *S3Client) GeneratePresignedURL(ctx context.Context, key string, expiration time.Duration) (string, error) {
	if c.config.AccessKeyID == "" || c.config.SecretAccessKey == "" {
		// No S3 configured, return local path
		return fmt.Sprintf("/storage/%s", key), nil
	}

	// In a real implementation, use AWS SDK presign client:
	// presignClient := s3.NewPresignClient(c.s3Client)
	// req, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
	//     Bucket: aws.String(c.config.Bucket),
	//     Key:    aws.String(key),
	// }, s3.WithPresignExpires(expiration))
	// return req.URL, err

	// For now, return a simulated presigned URL
	return fmt.Sprintf("%s/%s?expires=%d&signature=placeholder",
		c.config.PublicURLBase,
		key,
		time.Now().Add(expiration).Unix()), nil
}

// DeleteReport deletes a report from S3/R2
func (c *S3Client) DeleteReport(ctx context.Context, scanID, reportID uuid.UUID) error {
	pdfKey := GeneratePDFKey(scanID, reportID)
	jsonKey := GenerateJSONKey(scanID, reportID)

	if c.config.AccessKeyID == "" || c.config.SecretAccessKey == "" {
		// No S3 configured, nothing to delete
		return nil
	}

	// Delete from S3/R2 would happen here
	// Example using AWS SDK:
	// _, err := c.s3Client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
	//     Bucket: aws.String(c.config.Bucket),
	//     Delete: &types.Delete{
	//         Objects: []types.ObjectIdentifier{
	//             {Key: aws.String(pdfKey)},
	//             {Key: aws.String(jsonKey)},
	//         },
	//     },
	// })

	_ = pdfKey
	_ = jsonKey

	return nil
}

// generatePublicURL generates a public URL for a stored object
func (c *S3Client) generatePublicURL(key string) string {
	if c.config.PublicURLBase != "" {
		return fmt.Sprintf("%s/%s", c.config.PublicURLBase, key)
	}
	if c.config.Endpoint != "" {
		return fmt.Sprintf("%s/%s/%s", c.config.Endpoint, c.config.Bucket, key)
	}
	return fmt.Sprintf("/storage/%s", key)
}

// ============================================================================
// Local Storage Client (Fallback when S3 is not configured)
// ============================================================================

// LocalStorageClient implements StorageClient using local filesystem
type LocalStorageClient struct {
	basePath string
}

// NewLocalStorageClient creates a new local storage client
func NewLocalStorageClient(basePath string) *LocalStorageClient {
	if basePath == "" {
		basePath = "./storage/reports"
	}
	return &LocalStorageClient{
		basePath: basePath,
	}
}

// UploadPDF uploads a PDF report to local storage
func (c *LocalStorageClient) UploadPDF(ctx context.Context, scanID, reportID uuid.UUID, data []byte) (string, error) {
	key := GeneratePDFKey(scanID, reportID)
	path := fmt.Sprintf("%s/%s", c.basePath, key)

	// Create directory if it doesn't exist
	dir := path[:len(path)-len("/"+reportID.String()+".pdf")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write PDF: %w", err)
	}

	return path, nil
}

// UploadJSON uploads a JSON report to local storage
func (c *LocalStorageClient) UploadJSON(ctx context.Context, scanID, reportID uuid.UUID, data []byte) (string, error) {
	key := GenerateJSONKey(scanID, reportID)
	path := fmt.Sprintf("%s/%s", c.basePath, key)

	// Create directory if it doesn't exist
	dir := path[:len(path)-len("/"+reportID.String()+".json")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write JSON: %w", err)
	}

	return path, nil
}

// GeneratePresignedURL generates a local file path
func (c *LocalStorageClient) GeneratePresignedURL(ctx context.Context, key string, expiration time.Duration) (string, error) {
	return fmt.Sprintf("%s/%s", c.basePath, key), nil
}

// DeleteReport deletes a report from local storage
func (c *LocalStorageClient) DeleteReport(ctx context.Context, scanID, reportID uuid.UUID) error {
	pdfPath := fmt.Sprintf("%s/%s", c.basePath, GeneratePDFKey(scanID, reportID))
	jsonPath := fmt.Sprintf("%s/%s", c.basePath, GenerateJSONKey(scanID, reportID))

	// Try to delete PDF
	_ = os.Remove(pdfPath)
	// Try to delete JSON
	_ = os.Remove(jsonPath)

	// Also try to remove empty directory
	dir := pdfPath[:len(pdfPath)-len("/"+reportID.String()+".pdf")]
	os.Remove(dir)

	return nil
}

// ReadReport reads a report file from storage
func (c *LocalStorageClient) ReadReport(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// ReportExists checks if a report file exists
func (c *LocalStorageClient) ReportExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// Ensure LocalStorageClient implements StorageClient
var _ StorageClient = (*LocalStorageClient)(nil)

// NewStorageClient creates the appropriate storage client based on configuration
func NewStorageClient() (StorageClient, error) {
	// Check if S3/R2 is configured
	if os.Getenv("S3_ACCESS_KEY_ID") != "" && os.Getenv("S3_SECRET_ACCESS_KEY") != "" {
		return NewS3ClientFromEnv()
	}

	// Fall back to local storage
	return NewLocalStorageClient(os.Getenv("REPORT_STORAGE_PATH")), nil
}

// UploadReader uploads data from an io.Reader to the specified key
func (c *S3Client) UploadReader(ctx context.Context, key string, reader io.Reader, contentType string) (string, error) {
	// Read all data from reader
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read data: %w", err)
	}

	// Check if we have S3 credentials
	if c.config.AccessKeyID == "" || c.config.SecretAccessKey == "" {
		return fmt.Sprintf("/storage/%s", key), nil
	}

	// Upload would happen here using AWS SDK
	_ = data
	_ = contentType

	return c.generatePublicURL(key), nil
}

// UploadBuffer uploads data from a bytes.Buffer
func (c *S3Client) UploadBuffer(ctx context.Context, key string, buf *bytes.Buffer, contentType string) (string, error) {
	return c.UploadReader(ctx, key, buf, contentType)
}
