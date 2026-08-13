import React from 'react';
import type { SchemaFieldInfo } from '../../helpers/timeline-layout';
export declare const TimelineFieldRowContent: React.FC<{
    readonly field: SchemaFieldInfo;
    readonly rowDepth: number;
    readonly selected: boolean;
    readonly children: React.ReactNode;
}>;
