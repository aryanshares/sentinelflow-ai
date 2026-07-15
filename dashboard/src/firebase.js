/**
 * firebase.js — SentinalFlow AI
 * Firebase initialization: Auth + Firestore + Analytics
 */
import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';
import { getAnalytics, isSupported } from 'firebase/analytics';

const firebaseConfig = {
  apiKey:            'AIzaSyCwtAPwrIMBwRwuMhKRuLnhcf7VuSrSWX0',
  authDomain:        'sentinal-flow-ai.firebaseapp.com',
  projectId:         'sentinal-flow-ai',
  storageBucket:     'sentinal-flow-ai.firebasestorage.app',
  messagingSenderId: '348485101291',
  appId:             '1:348485101291:web:85d8a3939ebb51e3e840ae',
  measurementId:     'G-C1W8R1EG3W',
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db   = getFirestore(app);

// Analytics is browser-only — suppress SSR/node errors
isSupported().then(yes => yes ? getAnalytics(app) : null).catch(() => null);

export default app;
