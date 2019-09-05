/* eslint-disable */
import axios from 'axios';
import { showAlert } from './alerts';

const stripe = Stripe('pk_test_3Ot3Yxr35XnDe3nA56olRfqM00yI5FrF0Y');

export const bookTour = async tourId => {
  try {
    const session = await axios(
      `/api/v1/bookings/checkout-session/${tourId}`
    );

    await stripe.redirectToCheckout({
      sessionId: session.data.session.id
    });
  } catch (err) {
    console.log(err);
    showAlert('error', err);
  }
};
