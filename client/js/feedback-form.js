/**
 * Shared Feedback Form Component
 * Provides star rating and form submission functionality
 */

function escapeHtmlAttr(str) {
    if (str == null) return '';
    const s = String(str);
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

class FeedbackForm {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        this.options = {
            eventName: options.eventName || null,
            token: options.token || null, // Security token for external submissions
            showEventInput: options.showEventInput !== false,
            preserveEventName: options.preserveEventName !== false, // Keep event name after submit
            onSuccess: options.onSuccess || this.defaultSuccessHandler,
            onError: options.onError || this.defaultErrorHandler
        };
        this.rating = 0;
        this.state = 'ready'; // 'ready', 'submitting', 'success'
        this.init();
    }

    init() {
        this.render();
        this.attachEventListeners();
    }

    render() {
        this.container.innerHTML = `
            <form id="feedback-form" class="feedback-form">
                ${this.options.showEventInput ? `
                    <div class="form-group">
                        <label for="event-name">Event Name</label>
                        <input type="text" id="event-name" name="event_name" 
                               value="${escapeHtmlAttr(this.options.eventName || '')}" 
                               ${this.options.eventName ? 'readonly' : ''} 
                               required>
                    </div>
                ` : `
                    <input type="hidden" id="event-name" name="event_name" value="${escapeHtmlAttr(this.options.eventName || '')}">
                `}
                
                <div class="form-group">
                    <label id="rating-label" for="rating-value">Rating</label>
                    <div class="star-rating" id="star-rating" role="radiogroup" aria-labelledby="rating-label" tabindex="0" aria-describedby="rating-hint">
                        <span id="rating-hint" class="visually-hidden">Use arrow keys to choose 1 to 5 stars. Press Enter or Space to confirm.</span>
                        ${[1, 2, 3, 4, 5].map(num => `
                            <span class="star" id="star-${num}" role="radio" tabindex="-1" aria-checked="false" aria-posinset="${num}" aria-setsize="5" aria-label="${num} star${num > 1 ? 's' : ''}" data-rating="${num}">★</span>
                        `).join('')}
                    </div>
                    <input type="hidden" id="rating-value" name="rating" value="" required>
                </div>
                
                <div class="form-group">
                    <label for="comment">Comment (optional)</label>
                    <textarea id="comment" name="comment" rows="4" 
                              placeholder="Tell us about your experience..."></textarea>
                </div>
                
                <button type="submit" class="submit-btn" id="submit-btn">
                    <span class="btn-spinner"></span>
                    <span class="btn-text">Submit Feedback</span>
                </button>
            </form>
            
            <div id="form-message" class="form-message" aria-live="polite" role="status"></div>
        `;
    }

    attachEventListeners() {
        const ratingGroup = this.container.querySelector('#star-rating');
        const stars = this.container.querySelectorAll('.star');

        // Click and hover on stars
        stars.forEach(star => {
            star.addEventListener('click', (e) => {
                e.preventDefault();
                this.setRating(parseInt(e.currentTarget.dataset.rating));
                ratingGroup.setAttribute('aria-activedescendant', 'star-' + this.rating);
            });
            star.addEventListener('mouseenter', (e) => this.highlightStars(parseInt(e.target.dataset.rating)));
            star.addEventListener('mouseleave', () => this.highlightStars(this.rating));
        });

        // Single tab stop: keyboard on the radiogroup (arrows, Enter, Space)
        ratingGroup.addEventListener('keydown', (e) => {
            const key = e.key;
            let newRating = this.rating;
            if (key === 'ArrowRight' || key === 'ArrowDown') {
                e.preventDefault();
                newRating = Math.min(5, (this.rating || 0) + 1);
                this.setRating(newRating);
                ratingGroup.setAttribute('aria-activedescendant', 'star-' + newRating);
            } else if (key === 'ArrowLeft' || key === 'ArrowUp') {
                e.preventDefault();
                newRating = Math.max(1, (this.rating || 1) - 1);
                this.setRating(newRating);
                ratingGroup.setAttribute('aria-activedescendant', 'star-' + newRating);
            } else if (key === 'Home') {
                e.preventDefault();
                this.setRating(1);
                ratingGroup.setAttribute('aria-activedescendant', 'star-1');
            } else if (key === 'End') {
                e.preventDefault();
                this.setRating(5);
                ratingGroup.setAttribute('aria-activedescendant', 'star-5');
            } else if (key === 'Enter' || key === ' ') {
                e.preventDefault();
                if (!this.rating) {
                    this.setRating(1);
                    ratingGroup.setAttribute('aria-activedescendant', 'star-1');
                }
            }
        });

        // When the group receives focus, sync activedescendant so NVDA reads the current option (e.g. "3 of 5")
        ratingGroup.addEventListener('focus', () => {
            const r = this.rating || 1;
            ratingGroup.setAttribute('aria-activedescendant', 'star-' + r);
        });
        ratingGroup.addEventListener('blur', () => {
            if (!this.rating) this.highlightStars(0);
        });

        // Form submission
        const form = this.container.querySelector('#feedback-form');
        form.addEventListener('submit', (e) => this.handleSubmit(e));
    }

    setRating(rating) {
        this.rating = rating;
        this.container.querySelector('#rating-value').value = rating;
        this.highlightStars(rating);
    }

    highlightStars(rating) {
        const stars = this.container.querySelectorAll('.star');
        stars.forEach((star, index) => {
            const value = index + 1;
            const active = value <= rating;
            star.classList.toggle('active', active);
            star.setAttribute('aria-checked', active && value === rating ? 'true' : 'false');
        });
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        const submitBtn = this.container.querySelector('#submit-btn');
        
        // If in success state, "Add Another" was clicked - reset for new entry
        if (this.state === 'success') {
            this.resetForm();
            this.setButtonState('ready');
            this.hideMessage();
            return;
        }
        
        const eventName = this.container.querySelector('#event-name').value.trim();
        const rating = this.rating;
        const comment = this.container.querySelector('#comment').value.trim();

        if (!eventName) {
            this.showMessage('Please enter an event name.', 'error');
            const eventInput = this.container.querySelector('#event-name');
            if (eventInput) {
                eventInput.focus();
            }
            return;
        }

        if (!rating) {
            this.showMessage('Please select a rating.', 'error');
            const ratingGroup = this.container.querySelector('#star-rating');
            if (ratingGroup) {
                ratingGroup.focus();
            }
            return;
        }

        this.setButtonState('submitting');

        try {
            const response = await fetch('/api/feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    event_name: eventName,
                    rating: rating,
                    comment: comment || null,
                    ...(this.options.token && { token: this.options.token })
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.options.onSuccess.call(this, data);
                this.resetForm();
                this.setButtonState('success');
            } else {
                this.options.onError.call(this, data.error || 'Failed to submit feedback');
                this.setButtonState('ready');
            }
        } catch (error) {
            this.options.onError.call(this, 'Network error. Please try again.');
            this.setButtonState('ready');
        }
    }

    setButtonState(state) {
        this.state = state;
        const submitBtn = this.container.querySelector('#submit-btn');
        const btnText = submitBtn.querySelector('.btn-text');
        
        submitBtn.classList.remove('submitting', 'success');
        
        switch (state) {
            case 'submitting':
                submitBtn.disabled = true;
                submitBtn.classList.add('submitting');
                btnText.textContent = 'Submitting...';
                break;
            case 'success':
                submitBtn.disabled = false;
                submitBtn.classList.add('success');
                btnText.textContent = 'Add Another';
                break;
            case 'ready':
            default:
                submitBtn.disabled = false;
                btnText.textContent = 'Submit Feedback';
                break;
        }
    }

    hideMessage() {
        const messageEl = this.container.querySelector('#form-message');
        messageEl.style.display = 'none';
    }

    resetForm() {
        // Reset rating
        this.rating = 0;
        this.highlightStars(0);
        this.container.querySelector('#rating-value').value = '';
        
        // Reset comment
        this.container.querySelector('#comment').value = '';
        
        // Only reset event name if preserveEventName is false
        if (!this.options.preserveEventName && this.options.showEventInput && !this.options.eventName) {
            this.container.querySelector('#event-name').value = '';
        }
    }

    showMessage(message, type = 'success') {
        const messageEl = this.container.querySelector('#form-message');
        messageEl.textContent = message;
        messageEl.className = `form-message ${type}`;
        messageEl.style.display = 'block';
        messageEl.setAttribute('role', type === 'error' ? 'alert' : 'status');
        messageEl.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
        
        if (type === 'success') {
            setTimeout(() => {
                messageEl.style.display = 'none';
            }, 5000);
        }
    }

    defaultSuccessHandler(data) {
        this.showMessage('Thank you for your feedback!', 'success');
    }

    defaultErrorHandler(error) {
        this.showMessage(error, 'error');
    }
}

// Export for use in different contexts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FeedbackForm;
}
