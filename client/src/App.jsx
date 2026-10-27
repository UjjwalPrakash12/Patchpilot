import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import LandingPage from './pages/LandingPage'
import NewScanPage from './pages/NewScanPage'
import ScanPage from './pages/ScanPage'
import FindingDetailPage from './pages/FindingDetailPage'
import HistoryPage from './pages/HistoryPage'
import NotFoundPage from './pages/NotFoundPage'

function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<LandingPage />} />
        <Route path="/scan/new" element={<NewScanPage />} />
        <Route path="/scan/:scanId" element={<ScanPage />} />
        <Route path="/findings/:findingId" element={<FindingDetailPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}

export default App
