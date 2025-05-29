import * as React from 'react';
import {
    BulkDeleteButton,
    DatagridConfigurable,
    DateField,
    Identifier,
    TextField,
} from 'react-admin';

import ProductReferenceField from '../products/ProductReferenceField';
import UserReferenceField from '../users/UserReferenceField';
import StarRatingField from './StarRatingField';
import rowSx from './rowSx';

import BulkAcceptButton from './BulkAcceptButton';
import BulkRejectButton from './BulkRejectButton';

export interface ReviewListDesktopProps {
    selectedRow?: Identifier;
}

const ReviewsBulkActionButtons = () => (
    <>
        <BulkAcceptButton/>
        <BulkRejectButton/>
        <BulkDeleteButton/>
    </>
);

const ReviewListDesktop = ({selectedRow}: ReviewListDesktopProps) => (
    <DatagridConfigurable
        rowClick="edit"
        rowSx={rowSx(selectedRow)}
        bulkActionButtons={<ReviewsBulkActionButtons/>}
        sx={{
            '& .RaDatagrid-thead': {
                borderLeftColor: 'transparent',
                borderLeftWidth: 5,
                borderLeftStyle: 'solid',
            },
            '& .column-comment': {
                maxWidth: '18em',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
            },
        }}
    >
        <DateField source="reviewedDate" label={"Ngày đánh giá"}/>
        <UserReferenceField source={'reviewer.id'} link={false} label={"Người đánh giá"}/>
        <ProductReferenceField source="product.id" link={false} label={"Sản phẩm"}/>
        <StarRatingField size="small"/>
        <TextField source="content" label={"Nội dung"}/>
        <TextField source="type"/>
    </DatagridConfigurable>
);

export default ReviewListDesktop;
