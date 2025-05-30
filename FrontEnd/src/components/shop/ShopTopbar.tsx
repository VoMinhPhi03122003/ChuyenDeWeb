import PropTypes from "prop-types";
import React, { Fragment } from "react";
import ShopTopAction from "./ShopTopAction";

const ShopTopbar = ({
                        getLayout,
                        getFilterSortParams,
                        productCount,
                        sortedProductCount
                    } : any) => {
    return (
        <Fragment>
            {/* shop top action */}
            <ShopTopAction
                getLayout={getLayout}
                getFilterSortParams={getFilterSortParams}
                productCount={productCount}
                sortedProductCount={sortedProductCount}
            />
        </Fragment>
    );
};

ShopTopbar.propTypes = {
    getFilterSortParams: PropTypes.func,
    getLayout: PropTypes.func,
    productCount: PropTypes.number,
    sortedProductCount: PropTypes.number
};

export default ShopTopbar;
