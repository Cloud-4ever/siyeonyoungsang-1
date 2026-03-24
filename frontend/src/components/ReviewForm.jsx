import { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { reviewsAPI, uploadAPI } from '../api';
import StarRating from './StarRating';

function ReviewForm({ productId, onReviewAdded }) {
  const { user } = useAuth();
  const [rating, setRating] = useState(0);
  const [content, setContent] = useState('');
  const [photos, setPhotos] = useState([]);
  const [previews, setPreviews] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  if (!user) {
    return (
      <div className="review-form">
        <div className="review-form-login">
          <Link to="/login">로그인</Link> 후 리뷰를 작성할 수 있습니다
        </div>
      </div>
    );
  }

  const handleFileSelect = (e) => {
    const files = Array.from(e.target.files);
    const remainingSlots = 3 - photos.length;
    const newFiles = files.slice(0, remainingSlots);

    if (newFiles.length === 0) return;

    setPhotos((prev) => [...prev, ...newFiles]);

    newFiles.forEach((file) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        setPreviews((prev) => [...prev, reader.result]);
      };
      reader.readAsDataURL(file);
    });

    // Reset file input
    e.target.value = '';
  };

  const removePhoto = (index) => {
    setPhotos((prev) => prev.filter((_, i) => i !== index));
    setPreviews((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (rating === 0) {
      setError('별점을 선택해주세요');
      return;
    }

    if (!content.trim()) {
      setError('리뷰 내용을 입력해주세요');
      return;
    }

    setSubmitting(true);

    try {
      // Upload photos first
      const imageUrls = [];
      for (const photo of photos) {
        const res = await uploadAPI.uploadFile(photo);
        imageUrls.push(res.data.fileUrl);
      }

      // Submit review
      await reviewsAPI.create(productId, {
        rating,
        content: content.trim(),
        imageUrls,
      });

      // Reset form
      setRating(0);
      setContent('');
      setPhotos([]);
      setPreviews([]);

      if (onReviewAdded) {
        onReviewAdded();
      }
    } catch (err) {
      console.error('리뷰 작성 실패:', err);
      setError(err.response?.data?.error || '리뷰 작성에 실패했습니다');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="review-form">
      <h3 className="review-form-title">리뷰 작성</h3>
      <form onSubmit={handleSubmit}>
        <div className="review-form-stars">
          <label>별점</label>
          <StarRating rating={rating} size="1.5rem" interactive onChange={setRating} />
        </div>

        <textarea
          placeholder="상품에 대한 솔직한 리뷰를 남겨주세요"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          disabled={submitting}
        />

        <div className="review-form-upload">
          <span className="review-form-upload-label">
            사진 첨부 (최대 3장)
          </span>
          {photos.length < 3 && (
            <button
              type="button"
              className="review-form-upload-btn"
              onClick={() => fileInputRef.current?.click()}
              disabled={submitting}
            >
              📷 사진 추가
            </button>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            multiple
            style={{ display: 'none' }}
            onChange={handleFileSelect}
          />

          {previews.length > 0 && (
            <div className="review-form-previews">
              {previews.map((preview, index) => (
                <div key={index} className="review-form-preview">
                  <img src={preview} alt={`미리보기 ${index + 1}`} />
                  <button
                    type="button"
                    className="review-form-preview-remove"
                    onClick={() => removePhoto(index)}
                    disabled={submitting}
                  >
                    X
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {error && <div className="auth-error">{error}</div>}

        <button
          type="submit"
          className="btn btn-primary"
          disabled={submitting}
          style={{ width: '100%' }}
        >
          {submitting ? '등록 중...' : '리뷰 등록'}
        </button>
      </form>
    </div>
  );
}

export default ReviewForm;
