import { useState } from 'react';
import StarRating from './StarRating';

function ReviewList({ reviews }) {
  const [modalImage, setModalImage] = useState(null);

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  if (!reviews || reviews.length === 0) {
    return <div className="review-empty">아직 리뷰가 없습니다</div>;
  }

  return (
    <>
      <div className="review-list">
        {reviews.map((review) => (
          <div key={review.id} className="review-card">
            <div className="review-card-header">
              <div>
                <span className="review-card-user">{review.userName}</span>
                <div style={{ marginTop: '4px' }}>
                  <StarRating rating={review.rating} size="0.9rem" />
                </div>
              </div>
              <span className="review-card-date">{formatDate(review.createdAt)}</span>
            </div>
            <p className="review-card-content">{review.content}</p>
            {review.imageUrls && review.imageUrls.length > 0 && (
              <div className="review-card-images">
                {review.imageUrls.map((url, index) => (
                  <img
                    key={index}
                    src={url}
                    alt={`리뷰 이미지 ${index + 1}`}
                    onClick={() => setModalImage(url)}
                  />
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {modalImage && (
        <div className="image-modal-overlay" onClick={() => setModalImage(null)}>
          <img src={modalImage} alt="리뷰 이미지 확대" />
        </div>
      )}
    </>
  );
}

export default ReviewList;
