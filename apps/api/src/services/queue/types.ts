import { BatchJobStatus, BatchItemStatus } from '@phishnetra/shared';

export interface BatchItemTask {
  itemId: string;
  batchJobId: string;
  url: string;
  includePageAnalysis: boolean;
}

export interface QueueJob<T> {
  id: string;
  data: T;
  status: 'waiting' | 'active' | 'completed' | 'failed';
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  error?: string;
}

export interface QueueMetrics {
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  isPaused: boolean;
  workerConcurrency: number;
  driver: string;
}
