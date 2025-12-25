import React from 'react';
import { URLScanner } from '../components/URLScanner';

const ScannerPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">URL Scanner</h1>
        <p className="text-dark-400 mt-1">
          Analyze URLs for phishing threats using ML and rule-based detection
        </p>
      </div>
      <URLScanner />
    </div>
  );
};

export default ScannerPage;
