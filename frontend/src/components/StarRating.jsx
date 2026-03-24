import { useState } from 'react';

function StarRating({ rating = 0, size = '1rem', interactive = false, onChange }) {
  const [hoverRating, setHoverRating] = useState(0);

  const handleClick = (value) => {
    if (interactive && onChange) {
      onChange(value);
    }
  };

  const handleMouseEnter = (value) => {
    if (interactive) {
      setHoverRating(value);
    }
  };

  const handleMouseLeave = () => {
    if (interactive) {
      setHoverRating(0);
    }
  };

  const displayRating = hoverRating || rating;

  return (
    <span
      className={`star-rating ${interactive ? 'interactive' : ''}`}
      style={{ fontSize: size }}
    >
      {[1, 2, 3, 4, 5].map((value) => (
        <span
          key={value}
          className={`star ${value <= displayRating ? 'filled' : ''}`}
          onClick={() => handleClick(value)}
          onMouseEnter={() => handleMouseEnter(value)}
          onMouseLeave={handleMouseLeave}
          role={interactive ? 'button' : undefined}
          aria-label={interactive ? `${value}점` : undefined}
        >
          {value <= displayRating ? '\u2605' : '\u2606'}
        </span>
      ))}
    </span>
  );
}

export default StarRating;
