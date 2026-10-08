import EventEmitter from 'events';
import { prisma } from '../../db/prisma';
import { BatchItemTask, QueueMetrics } from './types';
import { AnalysisService } from '../AnalysisService';

export class AsyncAnalysisQueue extends EventEmitter {
  private static instance: AsyncAnalysisQueue;
  private taskQueue: BatchItemTask[] = [];
  private activeWorkers = 0;
  private maxConcurrency = 5;
  private isPaused = false;
  private completedCount = 0;
  private failedCount = 0;
  private analysisService = new AnalysisService();
  private cancelledJobs = new Set<string>();

  private constructor() {
    super();
  }

  public static getInstance(): AsyncAnalysisQueue {
    if (!AsyncAnalysisQueue.instance) {
      AsyncAnalysisQueue.instance = new AsyncAnalysisQueue();
    }
    return AsyncAnalysisQueue.instance;
  }

  /**
   * Enqueues batch item tasks into the async worker queue.
   */
  public enqueueBatch(tasks: BatchItemTask[]): void {
    this.taskQueue.push(...tasks);
    this.emit('batch:enqueued', { count: tasks.length });
    this.processNext();
  }

  /**
   * Cancels any pending tasks for a specific batch job.
   */
  public cancelBatchJob(batchJobId: string): void {
    this.cancelledJobs.add(batchJobId);
    // Filter out waiting tasks for this batch job
    this.taskQueue = this.taskQueue.filter((t) => t.batchJobId !== batchJobId);
  }

  /**
   * Main worker dispatcher loop.
   */
  private processNext(): void {
    if (this.isPaused) return;

    while (this.activeWorkers < this.maxConcurrency && this.taskQueue.length > 0) {
      const task = this.taskQueue.shift();
      if (!task) break;

      if (this.cancelledJobs.has(task.batchJobId)) {
        // Skip cancelled tasks
        continue;
      }

      this.activeWorkers++;
      this.executeTask(task).finally(() => {
        this.activeWorkers--;
        this.processNext();
      });
    }
  }

  /**
   * Executes single URL analysis inside worker pool and updates database records.
   */
  private async executeTask(task: BatchItemTask): Promise<void> {
    if (this.cancelledJobs.has(task.batchJobId)) {
      return;
    }

    try {
      // Mark BatchJob as RUNNING if it was QUEUED
      await prisma.batchJob.updateMany({
        where: { id: task.batchJobId, status: 'QUEUED' },
        data: { status: 'RUNNING' }
      });

      // Mark BatchItem as RUNNING
      await prisma.batchItem.update({
        where: { id: task.itemId },
        data: { status: 'RUNNING' }
      });

      // Run full multi-layer analysis
      const result = await this.analysisService.analyze(
        task.url,
        undefined,
        task.includePageAnalysis
      );

      // Update BatchItem with result
      await prisma.batchItem.update({
        where: { id: task.itemId },
        data: {
          status: 'COMPLETED',
          normalizedUrl: result.normalizedUrl,
          riskScore: result.riskScore,
          verdict: result.verdict,
          confidence: result.confidence,
          analysisId: result.analysisId
        }
      });

      this.completedCount++;
      await this.updateBatchJobProgress(task.batchJobId);
      this.emit('task:completed', { task, result });
    } catch (err: any) {
      console.error(`[AsyncAnalysisQueue] Task execution failed for ${task.url}:`, err.message);
      try {
        await prisma.batchItem.update({
          where: { id: task.itemId },
          data: {
            status: 'FAILED',
            errorMessage: err.message || 'Analysis processing failed'
          }
        });
      } catch (dbErr: any) {
        console.warn(`[AsyncAnalysisQueue] Failed to update item status: ${dbErr.message}`);
      }

      this.failedCount++;
      await this.updateBatchJobProgress(task.batchJobId);
      this.emit('task:failed', { task, error: err.message });
    }
  }

  /**
   * Recalculates and updates batch job completion counters and average risk scores.
   */
  private async updateBatchJobProgress(batchJobId: string): Promise<void> {
    try {
      const job = await prisma.batchJob.findUnique({
        where: { id: batchJobId },
        include: { items: true }
      });

      if (!job) return;

      const items = job.items;
      const total = items.length;
      const processed = items.filter((i: any) => i.status === 'COMPLETED' || i.status === 'FAILED').length;
      const completed = items.filter((i: any) => i.status === 'COMPLETED');
      const safeCount = completed.filter((i: any) => i.verdict === 'SAFE').length;
      const suspiciousCount = completed.filter((i: any) => i.verdict === 'SUSPICIOUS').length;
      const phishingCount = completed.filter((i: any) => i.verdict === 'PHISHING').length;
      const failedCount = items.filter((i: any) => i.status === 'FAILED').length;

      const scoredItems = completed.filter((i: any) => typeof i.riskScore === 'number');
      const avgRiskScore =
        scoredItems.length > 0
          ? Number((scoredItems.reduce((acc: number, curr: any) => acc + (curr.riskScore || 0), 0) / scoredItems.length).toFixed(1))
          : 0.0;

      const isAllDone = processed >= total;
      let status = job.status;

      if (isAllDone) {
        if (failedCount === total) {
          status = 'FAILED';
        } else if (failedCount > 0) {
          status = 'PARTIAL';
        } else {
          status = 'COMPLETED';
        }
      } else {
        status = 'RUNNING';
      }

      await prisma.batchJob.update({
        where: { id: batchJobId },
        data: {
          processedUrls: processed,
          safeCount,
          suspiciousCount,
          phishingCount,
          failedCount,
          avgRiskScore,
          status,
          completedAt: isAllDone ? new Date() : null
        }
      });
    } catch (err: any) {
      console.warn(`[AsyncAnalysisQueue] Failed to update batch progress: ${err.message}`);
    }
  }

  /**
   * Returns live operational metrics of the async worker pool.
   */
  public getMetrics(): QueueMetrics {
    return {
      waiting: this.taskQueue.length,
      active: this.activeWorkers,
      completed: this.completedCount,
      failed: this.failedCount,
      isPaused: this.isPaused,
      workerConcurrency: this.maxConcurrency,
      driver: 'In-Memory Async Worker Pool (BullMQ Compatible)'
    };
  }

  public pause(): void {
    this.isPaused = true;
  }

  public resume(): void {
    this.isPaused = false;
    this.processNext();
  }
}

export const analysisQueue = AsyncAnalysisQueue.getInstance();
