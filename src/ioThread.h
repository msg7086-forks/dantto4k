#pragma once

#include <vector>
#include <string>
#include <thread>
#include <span>
#include <istream>
#include <atomic>
#include <memory>
#include <algorithm>

#include "threadSafeQueue.h"

// A non-owning view of a buffer
using BufferView = std::span<const uint8_t>;

// The structure that will be passed from the producer to the consumer
struct FilledBuffer {
    std::unique_ptr<std::vector<uint8_t>> buffer;
    BufferView view;
};

// The structure that will be passed from the consumer to the producer
struct ProcessedBuffer {
    std::unique_ptr<std::vector<uint8_t>> buffer;
    BufferView remaining_view;
};

class IOThread {
public:
    // Constants are defined inside the class for better encapsulation
    static constexpr size_t NUM_BUFFERS = 3; // Use 3 buffers for smoother pipelining
    static constexpr size_t SPILL_OVER_AREA_SIZE = 1024 * 1024; // Typical spill over size is 2KB, reserve 1MB for it
    static constexpr size_t NEW_DATA_AREA_SIZE = 1024 * 1024 * 16; // 16MB
    static constexpr size_t BUFFER_SIZE = SPILL_OVER_AREA_SIZE + NEW_DATA_AREA_SIZE; // 17MB

    IOThread(std::istream& inputStream)
        : m_inputStream(inputStream), m_stopFlag(false)
    {
        // Create and prime the free buffers queue
        for (size_t i = 0; i < NUM_BUFFERS; ++i) {
            m_freeBuffersQueue.push(std::make_unique<std::vector<uint8_t>>(BUFFER_SIZE));
        }

        // Start the I/O thread
        m_thread = std::thread(&IOThread::threadFunc, this);
    }

    ~IOThread() {
        m_stopFlag = true;

        // Post empty data to unblock consumer and producer
        m_filledBuffersQueue.push({});
        m_processedBuffersQueue.push({});

        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    IOThread(const IOThread&) = delete;
    IOThread& operator=(const IOThread&) = delete;

    // Consumer gets a filled buffer to process
    FilledBuffer getFilledBuffer() {
        FilledBuffer filled;
        m_filledBuffersQueue.pop(filled);
        return filled;
    }

    // Consumer returns a processed buffer
    void returnProcessedBuffer(ProcessedBuffer processed) {
        m_processedBuffersQueue.push(std::move(processed));
    }

private:
    void threadFunc() {
        ProcessedBuffer processed_report;

        while (!m_stopFlag) {
            // 1. Get a free buffer to work with.
            std::unique_ptr<std::vector<uint8_t>> workBuffer;
            if (!m_freeBuffersQueue.pop(workBuffer)) {
                if (m_stopFlag) break;
                continue;
            }

            // 2. Get the report from the consumer about the last buffer they used.
            //    The first time this runs, the consumer will have sent an empty report.
            if (!m_processedBuffersQueue.pop(processed_report)) {
                 if (m_stopFlag) break;
                 continue;
            }

            // 3. The consumer has returned ownership of the buffer it was using.
            //    We can now put it back in the free queue for later use.
            if (processed_report.buffer) {
                m_freeBuffersQueue.push(std::move(processed_report.buffer));
            }

            // 4. Copy any leftover data from the consumer's report to the start of our new work buffer.
            size_t remainingSize = 0;
            if (!processed_report.remaining_view.empty()) {
                remainingSize = processed_report.remaining_view.size();
                if (remainingSize > SPILL_OVER_AREA_SIZE) {
                    // This is a safeguard, should not happen with correct consumer logic
                    remainingSize = SPILL_OVER_AREA_SIZE;
                }
                std::copy_n(processed_report.remaining_view.begin(), remainingSize, workBuffer->begin());
            }

            // 5. Read new data into the work buffer, right after the leftover data.
            m_inputStream.read(reinterpret_cast<char*>(workBuffer->data() + remainingSize), NEW_DATA_AREA_SIZE);
            std::streamsize bytesRead = m_inputStream.gcount();

            if (bytesRead == 0 && m_inputStream.eof()) {
                m_filledBuffersQueue.push({}); // Signal EOF
                break;
            }

            // 6. Prepare the filled buffer and send it to the consumer.
            FilledBuffer filled;
            filled.buffer = std::move(workBuffer);
            filled.view = BufferView(filled.buffer->data(), remainingSize + bytesRead);
            m_filledBuffersQueue.push(std::move(filled));
        }
    }

    std::istream& m_inputStream;
    std::thread m_thread;
    std::atomic<bool> m_stopFlag;

    // Pipeline queues
    ThreadSafeQueue<std::unique_ptr<std::vector<uint8_t>>> m_freeBuffersQueue;
    ThreadSafeQueue<FilledBuffer> m_filledBuffersQueue;
    ThreadSafeQueue<ProcessedBuffer> m_processedBuffersQueue;
};
